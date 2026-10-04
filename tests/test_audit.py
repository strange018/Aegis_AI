"""
Unit Tests for Audit Logging and Security Event Recording.
"""

from database import get_audit_logs, insert_audit_log
from audit import log_event, AuditEvent
from auth import authenticate_user


def test_audit_log_creation(temp_db):
    """Test creating and retrieving structured audit log records."""
    log_id = log_event(
        AuditEvent.USER_CREATED,
        "Admin created user test_user",
        user_id="U_ADM",
        username="admin",
        status="SUCCESS",
        db_path=temp_db
    )
    assert log_id > 0

    logs = get_audit_logs(limit=10, db_path=temp_db)
    assert len(logs) == 1
    assert logs[0]["event_type"] == AuditEvent.USER_CREATED.value
    assert logs[0]["username"] == "admin"
    assert logs[0]["status"] == "SUCCESS"


def test_failed_login_creates_audit_log(populated_db):
    """Test that failed logins are immutably logged."""
    authenticate_user("test_admin", "WrongPassword", db_path=populated_db)

    logs = get_audit_logs(event_type=AuditEvent.LOGIN_FAILED.value, db_path=populated_db)
    assert len(logs) >= 1
    assert "Invalid password" in logs[0]["description"]


def test_password_redaction_in_audit_logs(temp_db):
    """Verify that password strings are never recorded in plaintext in audit descriptions."""
    log_event(
        AuditEvent.USER_CREATED,
        "User created with password=SecretPassword123 and token=BearerXYZ",
        username="admin",
        db_path=temp_db
    )

    logs = get_audit_logs(limit=5, db_path=temp_db)
    assert len(logs) == 1
    assert "SecretPassword123" not in logs[0]["description"]
    assert "[REDACTED]" in logs[0]["description"]
