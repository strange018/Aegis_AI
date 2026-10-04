"""
Integration and Validation Tests for CSV User Import.
"""

import tempfile
import os
from pathlib import Path
import pytest

from import_users import import_users_from_csv
from database import get_all_users, get_user_by_username
from auth import verify_password, update_user_password, hash_password


def test_import_actual_users_csv(temp_db):
    """Test importing from the real users.csv provided in workspace."""
    csv_file = Path(__file__).resolve().parent.parent / "users.csv"
    assert csv_file.exists(), "users.csv must exist in workspace"

    report = import_users_from_csv(
        csv_path=str(csv_file),
        default_password="CustomTestPass@123",
        db_path=temp_db
    )

    # users.csv has 30 rows
    assert report["summary"]["total"] == 30
    assert report["summary"]["inserted"] == 30
    assert report["summary"]["errors"] == 0

    all_users = get_all_users(db_path=temp_db)
    assert len(all_users) == 30

    # Verify specific roles from dataset
    arun = get_user_by_username("arun", db_path=temp_db)
    assert arun["role"] == "admin"
    assert verify_password(arun["password_hash"], "CustomTestPass@123") is True

    priya = get_user_by_username("priya", db_path=temp_db)
    assert priya["role"] == "researcher"

    rahul = get_user_by_username("rahul", db_path=temp_db)
    assert rahul["role"] == "viewer"


def test_import_idempotency_preserves_passwords(temp_db):
    """Test that re-importing the CSV does NOT overwrite existing user passwords or duplicate users."""
    csv_file = Path(__file__).resolve().parent.parent / "users.csv"

    # First import
    import_users_from_csv(str(csv_file), default_password="InitialPassword", db_path=temp_db)

    # Change password for user 'arun'
    arun = get_user_by_username("arun", db_path=temp_db)
    update_user_password(arun["user_id"], hash_password("ArunNewPassword!"), db_path=temp_db)

    # Run second import with a different default password
    report2 = import_users_from_csv(str(csv_file), default_password="DifferentDefault", db_path=temp_db)

    assert report2["summary"]["inserted"] == 0
    assert report2["summary"]["skipped"] == 30

    # Ensure Arun's modified password was preserved
    arun_after = get_user_by_username("arun", db_path=temp_db)
    assert verify_password(arun_after["password_hash"], "ArunNewPassword!") is True
    assert verify_password(arun_after["password_hash"], "DifferentDefault") is False


def test_import_malformed_records(temp_db):
    """Test CSV importer rejects invalid roles, missing fields, and batch duplicates."""
    malformed_csv_content = """user_id,username,role,permissions
U100,good_user,viewer,View results
U101,bad_role_user,superadmin,Bypass all
U102,,researcher,Run AI
,missing_id,admin,Manage users
U103,duplicate_uname,researcher,Run AI
U104,duplicate_uname,viewer,View results
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False, encoding="utf-8") as f:
        f.write(malformed_csv_content)
        temp_csv_path = f.name

    try:
        report = import_users_from_csv(temp_csv_path, default_password="Pass@123", db_path=temp_db)

        assert report["summary"]["inserted"] == 2  # good_user and first duplicate_uname
        assert report["summary"]["errors"] == 4    # bad_role, empty username, missing id, second duplicate

        error_reasons = [e["reason"] for e in report["errors"]]
        assert any("Invalid role" in r for r in error_reasons)
        assert any("Missing required fields" in r for r in error_reasons)
        assert any("Duplicate" in r for r in error_reasons)

        # Confirm only valid users exist in DB
        assert get_user_by_username("good_user", db_path=temp_db) is not None
        assert get_user_by_username("bad_role_user", db_path=temp_db) is None
    finally:
        if os.path.exists(temp_csv_path):
            os.remove(temp_csv_path)
