"""
CSV Import and Validation Module for RBAC AI Platform.

Inspects, validates, and securely imports user records from CSV into SQLite.
Treats CSV role and permission fields as untrusted input, enforcing server-side RBAC policy.
Prevents overwriting existing passwords and provides a detailed import report.
"""

import csv
import re
import argparse
from pathlib import Path
from typing import Dict, Any, List, Optional

from database import init_db, get_user_by_username, get_user_by_id, insert_user, update_user_role
from permissions import Role
from auth import hash_password
from audit import log_event, AuditEvent
from config import DEFAULT_DB_PATH, DEFAULT_USER_PASSWORD


def validate_username(username: str) -> bool:
    """Validate username: 3-30 chars, alphanumeric or underscores."""
    if not username or not isinstance(username, str):
        return False
    return bool(re.match(r"^[a-zA-Z0-9_]{2,30}$", username.strip()))


def validate_user_id(user_id: str) -> bool:
    """Validate user_id: non-empty, alphanumeric."""
    if not user_id or not isinstance(user_id, str):
        return False
    return bool(re.match(r"^[a-zA-Z0-9_-]{2,30}$", user_id.strip()))


def import_users_from_csv(
    csv_path: str,
    default_password: str = DEFAULT_USER_PASSWORD,
    update_roles_if_exists: bool = False,
    db_path: Optional[str] = None,
    acting_user: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Parses and validates CSV user records and idempotently loads them into SQLite.

    Returns a comprehensive report:
    {
        "total_rows": int,
        "inserted": List[Dict],
        "updated": List[Dict],
        "skipped": List[Dict],
        "errors": List[Dict],
        "summary": Dict[str, int]
    }
    """
    path = Path(csv_path)
    if not path.exists():
        raise FileNotFoundError(f"CSV file not found at: {csv_path}")

    # Ensure DB tables are ready
    init_db(db_path)

    report = {
        "total_rows": 0,
        "inserted": [],
        "updated": [],
        "skipped": [],
        "errors": [],
        "summary": {
            "total": 0,
            "inserted": 0,
            "updated": 0,
            "skipped": 0,
            "errors": 0
        }
    }

    seen_usernames_in_batch = set()
    seen_ids_in_batch = set()

    with open(path, mode="r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        
        # Check required columns
        fieldnames = [c.strip().lower() for c in (reader.fieldnames or [])]
        required_cols = {"user_id", "username", "role"}
        if not required_cols.issubset(set(fieldnames)):
            raise ValueError(
                f"Invalid CSV structure. Expected columns {required_cols}, found: {reader.fieldnames}"
            )

        row_idx = 1
        for raw_row in reader:
            row_idx += 1
            report["total_rows"] += 1
            
            # Normalize row keys
            row = {k.strip().lower(): (v.strip() if v else "") for k, v in raw_row.items()}
            
            user_id = row.get("user_id", "")
            username = row.get("username", "").lower()
            role = row.get("role", "").lower()
            raw_permissions = row.get("permissions", "")

            # Validation 1: Missing values
            if not user_id or not username or not role:
                report["errors"].append({
                    "row": row_idx,
                    "user_id": user_id,
                    "username": username,
                    "reason": "Missing required fields (user_id, username, or role)."
                })
                continue

            # Validation 2: User ID format
            if not validate_user_id(user_id):
                report["errors"].append({
                    "row": row_idx,
                    "user_id": user_id,
                    "username": username,
                    "reason": f"Invalid user_id format '{user_id}'."
                })
                continue

            # Validation 3: Username format
            if not validate_username(username):
                report["errors"].append({
                    "row": row_idx,
                    "user_id": user_id,
                    "username": username,
                    "reason": f"Invalid username format '{username}'."
                })
                continue

            # Validation 4: Role validity (Server-side RBAC policy)
            if not Role.is_valid(role):
                report["errors"].append({
                    "row": row_idx,
                    "user_id": user_id,
                    "username": username,
                    "reason": f"Invalid role '{role}'. Permitted roles are: {Role.valid_roles()}."
                })
                continue

            # Validation 5: In-batch duplicate check
            if username in seen_usernames_in_batch or user_id in seen_ids_in_batch:
                report["errors"].append({
                    "row": row_idx,
                    "user_id": user_id,
                    "username": username,
                    "reason": "Duplicate record within the same CSV batch."
                })
                continue

            seen_usernames_in_batch.add(username)
            seen_ids_in_batch.add(user_id)

            # Check existing user in Database (Idempotent handling)
            existing_user = get_user_by_username(username, db_path=db_path)
            existing_by_id = get_user_by_id(user_id, db_path=db_path)

            if existing_user or existing_by_id:
                # Existing account
                matched_user = existing_user or existing_by_id
                if update_roles_if_exists and matched_user["role"] != role:
                    update_user_role(matched_user["user_id"], role, db_path=db_path)
                    report["updated"].append({
                        "row": row_idx,
                        "user_id": matched_user["user_id"],
                        "username": matched_user["username"],
                        "old_role": matched_user["role"],
                        "new_role": role,
                        "note": "Role updated; existing password preserved."
                    })
                else:
                    report["skipped"].append({
                        "row": row_idx,
                        "user_id": matched_user["user_id"],
                        "username": matched_user["username"],
                        "role": matched_user["role"],
                        "reason": "User already exists; existing credentials and status preserved."
                    })
                continue

            # New user insertion with secure password hash
            pwd_hash = hash_password(default_password)
            insert_user(
                user_id=user_id,
                username=username,
                password_hash=pwd_hash,
                role=role,
                is_active=1,
                db_path=db_path
            )

            report["inserted"].append({
                "row": row_idx,
                "user_id": user_id,
                "username": username,
                "role": role,
                "note": "Created with default password."
            })

    # Summary counts
    report["summary"]["total"] = report["total_rows"]
    report["summary"]["inserted"] = len(report["inserted"])
    report["summary"]["updated"] = len(report["updated"])
    report["summary"]["skipped"] = len(report["skipped"])
    report["summary"]["errors"] = len(report["errors"])

    # Log audit event for import
    actor_name = acting_user.get("username", "system_cli") if acting_user else "system_cli"
    actor_id = acting_user.get("user_id") if acting_user else None

    log_event(
        AuditEvent.CSV_IMPORT_COMPLETED,
        f"CSV imported from '{path.name}'. Inserted: {report['summary']['inserted']}, "
        f"Skipped: {report['summary']['skipped']}, Errors: {report['summary']['errors']}",
        user_id=actor_id,
        username=actor_name,
        status="SUCCESS",
        db_path=db_path
    )

    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Import users from CSV into SQLite with RBAC validation.")
    parser.add_argument("--csv", default="users.csv", help="Path to users.csv file")
    parser.add_argument("--db", default=DEFAULT_DB_PATH, help="Path to SQLite database file")
    parser.add_argument("--default-password", default=DEFAULT_USER_PASSWORD, help="Initial default password for new users")
    parser.add_argument("--update-roles", action="store_true", help="Update role if user already exists")

    args = parser.parse_args()

    print(f"[*] Initializing database at: {args.db}")
    init_db(args.db)

    print(f"[*] Importing users from: {args.csv}")
    res = import_users_from_csv(
        csv_path=args.csv,
        default_password=args.default_password,
        update_roles_if_exists=args.update_roles,
        db_path=args.db
    )

    print("\n--- IMPORT SUMMARY REPORT ---")
    print(f"Total Rows Processed : {res['summary']['total']}")
    print(f"Successfully Inserted: {res['summary']['inserted']}")
    print(f"Existing Users Skipped: {res['summary']['skipped']}")
    print(f"Existing Users Updated: {res['summary']['updated']}")
    print(f"Malformed / Error Rows: {res['summary']['errors']}")

    if res["errors"]:
        print("\n[!] Errors Encountered:")
        for err in res["errors"]:
            print(f"  - Row {err['row']}: User ID='{err.get('user_id')}', Username='{err.get('username')}' -> {err['reason']}")

    if res["inserted"]:
        print(f"\n[+] Imported {len(res['inserted'])} users successfully with default password '{args.default_password}'.")
