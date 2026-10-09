"""
Audit Logging Module for RBAC AI Platform.

Ensures that all security-sensitive events (authentication, authorization checks,
user management, and privilege escalation attempts) are immutably logged into SQLite
and appended to a plain-text security log file.
Sensitive information such as plain passwords are NEVER logged.
"""

import re
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional
from database import insert_audit_log
from config import DEFAULT_DB_PATH, SECURITY_LOG_FILENAME
from network import get_client_ip


class AuditEvent(str, Enum):
    # Authentication Events
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILED = "LOGIN_FAILED"
    LOGOUT = "LOGOUT"
    ACCOUNT_LOCKED = "ACCOUNT_LOCKED"

    # User Management Events
    USER_CREATED = "USER_CREATED"
    USER_UPDATED = "USER_UPDATED"
    USER_ROLE_CHANGED = "USER_ROLE_CHANGED"
    USER_ACTIVATED = "USER_ACTIVATED"
    USER_DEACTIVATED = "USER_DEACTIVATED"
    PASSWORD_RESET = "PASSWORD_RESET"

    # Authorization & Security Violation Events
    ACCESS_GRANTED = "ACCESS_GRANTED"
    ACCESS_DENIED = "ACCESS_DENIED"
    PRIVILEGE_ESCALATION_BLOCKED = "PRIVILEGE_ESCALATION_BLOCKED"
    UNAUTHORIZED_RESOURCE_ATTEMPT = "UNAUTHORIZED_RESOURCE_ATTEMPT"

    # Operational AI & System Events
    AI_TASK_EXECUTED = "AI_TASK_EXECUTED"
    AI_TASK_DENIED = "AI_TASK_DENIED"
    CSV_IMPORT_COMPLETED = "CSV_IMPORT_COMPLETED"
    DATABASE_BOOTSTRAP = "DATABASE_BOOTSTRAP"

    # Login IP Security Events
    LOGIN_IP_REGISTERED = "LOGIN_IP_REGISTERED"
    NEW_IP_LOGIN = "NEW_IP_LOGIN"


def get_security_log_path(db_path: Optional[str] = None) -> Path:
    """The security log file lives next to the database it belongs to."""
    return Path(db_path if db_path else DEFAULT_DB_PATH).resolve().parent / SECURITY_LOG_FILENAME


def write_security_log_line(
    event_type: str,
    description: str,
    username: Optional[str],
    status: str,
    ip_address: str,
    db_path: Optional[str] = None
) -> None:
    """Append one event to the plain-text security log. Never breaks the caller."""
    line = (
        f"{datetime.now(timezone.utc).isoformat()} | {status:<8} | {event_type:<30} | "
        f"user={username or '-'} | ip={ip_address} | {description}\n"
    )
    try:
        with open(get_security_log_path(db_path), "a", encoding="utf-8") as f:
            f.write(line)
    except OSError:
        pass


def log_event(
    event_type: AuditEvent,
    description: str,
    user_id: Optional[str] = None,
    username: Optional[str] = None,
    status: str = "SUCCESS",
    ip_address: Optional[str] = None,
    db_path: Optional[str] = None
) -> int:
    """
    Standardized logger for security audit events.
    Applies regex sanitization to ensure sensitive values are redacted.
    If no IP is given, the IP of the current Streamlit client is recorded.
    """
    if not ip_address:
        ip_address = get_client_ip()

    # Sanitize description to redact sensitive parameter values like password=xyz or token=abc
    clean_desc = re.sub(
        r"(password|token|secret|key|pwd)\s*=\s*([^\s,;]+)",
        r"\1=[REDACTED]",
        description,
        flags=re.IGNORECASE
    )
    
    evt_str = event_type.value if hasattr(event_type, "value") else str(event_type)

    write_security_log_line(evt_str, clean_desc, username, status, ip_address, db_path=db_path)

    return insert_audit_log(
        event_type=evt_str,
        description=clean_desc,
        user_id=user_id,
        username=username,
        status=status,
        ip_address=ip_address,
        db_path=db_path
    )

