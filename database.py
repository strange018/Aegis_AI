"""
Database Layer for RBAC AI Platform.

Uses SQLite with persistent storage, parameterized queries for SQL injection prevention,
and strict foreign key constraints.
"""

import sqlite3
import json
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from pathlib import Path

from config import DEFAULT_DB_PATH


def get_db_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """
    Creates and returns a SQLite database connection with row factory
    and enabled foreign key enforcement.
    """
    path = db_path if db_path else DEFAULT_DB_PATH
    # Ensure parent directory exists
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    
    conn = sqlite3.connect(path, timeout=20.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db(db_path: Optional[str] = None) -> None:
    """
    Initializes database schema if tables do not already exist.
    Safe and idempotent.
    """
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        
        # 1. Users Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
        """)

        # Indexes for fast lookup and security queries
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);")

        # 2. Audit Logs Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT,
                username TEXT,
                event_type TEXT NOT NULL,
                description TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'SUCCESS',
                ip_address TEXT DEFAULT '127.0.0.1',
                timestamp TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE SET NULL
            );
        """)

        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp DESC);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_logs(event_type);")

        # 3. AI Research Experiments Table (for Researcher features)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ai_experiments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                username TEXT NOT NULL,
                analysis_type TEXT NOT NULL,
                input_snippet TEXT NOT NULL,
                summary_output TEXT NOT NULL,
                metrics_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
            );
        """)

        # 4. Login History Table (IP address of every successful login)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS login_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                username TEXT NOT NULL,
                role TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                is_new_ip INTEGER NOT NULL DEFAULT 0 CHECK (is_new_ip IN (0, 1)),
                known_ips TEXT NOT NULL DEFAULT '',
                timestamp TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
            );
        """)

        cursor.execute("CREATE INDEX IF NOT EXISTS idx_login_user ON login_history(user_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_login_new_ip ON login_history(is_new_ip);")

        conn.commit()


# ==========================================
# User Repository Functions
# ==========================================

def get_user_by_username(username: str, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Fetch single user by username (case-insensitive)."""
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ? COLLATE NOCASE", (username.strip(),))
        row = cursor.fetchone()
        return dict(row) if row else None


def get_user_by_id(user_id: str, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Fetch single user by user_id."""
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE user_id = ?", (user_id.strip(),))
        row = cursor.fetchone()
        return dict(row) if row else None


def get_all_users(db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Fetch all users ordered by creation date."""
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT user_id, username, role, is_active, created_at, updated_at FROM users ORDER BY user_id ASC")
        return [dict(r) for r in cursor.fetchall()]


def insert_user(user_id: str, username: str, password_hash: str, role: str, is_active: int = 1, db_path: Optional[str] = None) -> bool:
    """Insert a new user record."""
    now_iso = datetime.now(timezone.utc).isoformat()
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO users (user_id, username, password_hash, role, is_active, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (user_id.strip(), username.strip().lower(), password_hash, role.strip().lower(), is_active, now_iso, now_iso))
        conn.commit()
        return True


def update_user_role(user_id: str, new_role: str, db_path: Optional[str] = None) -> bool:
    """Update user role with timestamp."""
    now_iso = datetime.now(timezone.utc).isoformat()
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE users SET role = ?, updated_at = ? WHERE user_id = ?
        """, (new_role.strip().lower(), now_iso, user_id.strip()))
        conn.commit()
        return cursor.rowcount > 0


def set_user_active_status(user_id: str, is_active: bool, db_path: Optional[str] = None) -> bool:
    """Activate or deactivate user account."""
    now_iso = datetime.now(timezone.utc).isoformat()
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE users SET is_active = ?, updated_at = ? WHERE user_id = ?
        """, (1 if is_active else 0, now_iso, user_id.strip()))
        conn.commit()
        return cursor.rowcount > 0


def update_user_password(user_id: str, new_password_hash: str, db_path: Optional[str] = None) -> bool:
    """Update user password hash."""
    now_iso = datetime.now(timezone.utc).isoformat()
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE users SET password_hash = ?, updated_at = ? WHERE user_id = ?
        """, (new_password_hash, now_iso, user_id.strip()))
        conn.commit()
        return cursor.rowcount > 0


def count_users(db_path: Optional[str] = None) -> int:
    """Return total number of registered users."""
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users")
        return cursor.fetchone()[0]


# ==========================================
# Audit Log Repository Functions
# ==========================================

def insert_audit_log(
    event_type: str,
    description: str,
    user_id: Optional[str] = None,
    username: Optional[str] = None,
    status: str = "SUCCESS",
    ip_address: str = "127.0.0.1",
    db_path: Optional[str] = None
) -> int:
    """
    Records an immutable audit event in the database.
    Passwords and sensitive raw tokens must never be passed into description.
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        
        # Verify if user_id exists in users table to satisfy foreign key integrity safely
        validated_user_id = None
        if user_id:
            cursor.execute("SELECT 1 FROM users WHERE user_id = ?", (user_id,))
            if cursor.fetchone():
                validated_user_id = user_id

        cursor.execute("""
            INSERT INTO audit_logs (user_id, username, event_type, description, status, ip_address, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (validated_user_id, username, event_type.strip(), description.strip(), status.strip(), ip_address, now_iso))
        conn.commit()
        return cursor.lastrowid


def get_audit_logs(
    limit: int = 100,
    event_type: Optional[str] = None,
    user_filter: Optional[str] = None,
    db_path: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Retrieve filtered audit logs in descending chronological order."""
    query = "SELECT * FROM audit_logs WHERE 1=1"
    params: List[Any] = []

    if event_type and event_type != "ALL":
        query += " AND event_type = ?"
        params.append(event_type)

    if user_filter and user_filter.strip():
        query += " AND (username LIKE ? OR user_id LIKE ?)"
        wildcard = f"%{user_filter.strip()}%"
        params.extend([wildcard, wildcard])

    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(query, tuple(params))
        return [dict(r) for r in cursor.fetchall()]


# ==========================================
# AI Experiment Repository Functions
# ==========================================

def insert_ai_experiment(
    user_id: str,
    username: str,
    analysis_type: str,
    input_snippet: str,
    summary_output: str,
    metrics_json: str,
    db_path: Optional[str] = None
) -> int:
    """Save an AI experiment execution record."""
    now_iso = datetime.now(timezone.utc).isoformat()
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        
        valid_user_id = user_id
        cursor.execute("SELECT 1 FROM users WHERE user_id = ?", (user_id,))
        if not cursor.fetchone():
            cursor.execute("SELECT user_id FROM users LIMIT 1")
            row = cursor.fetchone()
            valid_user_id = row[0] if row else None

        if valid_user_id:
            cursor.execute("""
                INSERT INTO ai_experiments (user_id, username, analysis_type, input_snippet, summary_output, metrics_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (valid_user_id, username, analysis_type, input_snippet, summary_output, metrics_json, now_iso))
            conn.commit()
            return cursor.lastrowid
        return 0


def get_ai_experiments(limit: int = 50, user_id: Optional[str] = None, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieve saved AI experiment runs."""
    query = "SELECT * FROM ai_experiments WHERE 1=1"
    params: List[Any] = []

    if user_id:
        query += " AND user_id = ?"
        params.append(user_id)

    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(query, tuple(params))
        results = []
        for r in cursor.fetchall():
            item = dict(r)
            try:
                item["metrics"] = json.loads(item["metrics_json"])
            except Exception:
                item["metrics"] = {}
            results.append(item)
        return results


# ==========================================
# Login History / IP Tracking Functions
# ==========================================

def get_known_ips(user_id: str, db_path: Optional[str] = None) -> List[str]:
    """Return the distinct IP addresses a user has previously logged in from (oldest first)."""
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT ip_address FROM login_history WHERE user_id = ?
            GROUP BY ip_address ORDER BY MIN(id) ASC
        """, (user_id,))
        return [r["ip_address"] for r in cursor.fetchall()]


def insert_login_record(
    user_id: str,
    username: str,
    role: str,
    ip_address: str,
    is_new_ip: bool,
    known_ips: List[str],
    db_path: Optional[str] = None
) -> int:
    """Store the IP address of a successful login."""
    now_iso = datetime.now(timezone.utc).isoformat()
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO login_history (user_id, username, role, ip_address, is_new_ip, known_ips, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (user_id, username, role, ip_address, 1 if is_new_ip else 0, ", ".join(known_ips), now_iso))
        conn.commit()
        return cursor.lastrowid


def get_login_history(
    limit: int = 100,
    only_new_ip: bool = False,
    user_id: Optional[str] = None,
    db_path: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Retrieve login records, newest first. `only_new_ip` returns just the flagged ones."""
    query = "SELECT * FROM login_history WHERE 1=1"
    params: List[Any] = []

    if only_new_ip:
        query += " AND is_new_ip = 1"
    if user_id:
        query += " AND user_id = ?"
        params.append(user_id)

    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(query, tuple(params))
        return [dict(r) for r in cursor.fetchall()]


def get_user_ip_summary(db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Per-user summary of logins: number of logins, distinct IPs and flagged logins."""
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT user_id, username, role,
                   COUNT(*) AS total_logins,
                   COUNT(DISTINCT ip_address) AS distinct_ips,
                   SUM(is_new_ip) AS new_ip_alerts,
                   GROUP_CONCAT(DISTINCT ip_address) AS ip_addresses,
                   MAX(timestamp) AS last_login
            FROM login_history
            GROUP BY user_id
            ORDER BY last_login DESC
        """)
        return [dict(r) for r in cursor.fetchall()]


# ==========================================
# System Metrics
# ==========================================

def get_system_metrics(db_path: Optional[str] = None) -> Dict[str, Any]:
    """Calculate aggregate system metrics for dashboard summaries."""
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM users")
        total_users = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM users WHERE is_active = 1")
        active_users = cursor.fetchone()[0]

        cursor.execute("SELECT role, COUNT(*) as count FROM users GROUP BY role")
        role_counts = {r["role"]: r["count"] for r in cursor.fetchall()}

        cursor.execute("SELECT COUNT(*) FROM audit_logs")
        total_audit_events = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM audit_logs WHERE event_type = 'LOGIN_FAILED'")
        failed_logins = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM ai_experiments")
        total_ai_runs = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM login_history WHERE is_new_ip = 1")
        new_ip_alerts = cursor.fetchone()[0]

        return {
            "total_users": total_users,
            "active_users": active_users,
            "inactive_users": total_users - active_users,
            "role_counts": role_counts,
            "total_audit_events": total_audit_events,
            "failed_logins": failed_logins,
            "total_ai_runs": total_ai_runs,
            "new_ip_alerts": new_ip_alerts
        }
