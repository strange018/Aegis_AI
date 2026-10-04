"""
Audit Logging Module for RBAC AI Platform.

Ensures that all security-sensitive events (authentication, authorization checks,
user management, and privilege escalation attempts) are immutably logged into SQLite.
Sensitive information such as plain passwords are NEVER logged.
"""

import re
from enum import Enum
from typing import Optional
from database import insert_audit_log


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


def log_event(
    event_type: AuditEvent,
    description: str,
    user_id: Optional[str] = None,
    username: Optional[str] = None,
    status: str = "SUCCESS",
    ip_address: str = "127.0.0.1",
    db_path: Optional[str] = None
) -> int:
    """
    Standardized logger for security audit events.
    Applies regex sanitization to ensure sensitive values are redacted.
    """
    # Sanitize description to redact sensitive parameter values like password=xyz or token=abc
    clean_desc = re.sub(
        r"(password|token|secret|key|pwd)\s*=\s*([^\s,;]+)",
        r"\1=[REDACTED]",
        description,
        flags=re.IGNORECASE
    )
    
    evt_str = event_type.value if hasattr(event_type, "value") else str(event_type)
    
    return insert_audit_log(
        event_type=evt_str,
        description=clean_desc,
        user_id=user_id,
        username=username,
        status=status,
        ip_address=ip_address,
        db_path=db_path
    )

