"""
Tests for Login IP Tracking and New-IP Alerting.
"""

from auth import authenticate_user
from audit import get_security_log_path
from database import get_login_history, get_audit_logs, get_known_ips, get_system_metrics


def test_first_login_registers_ip(populated_db):
    """The first successful login stores the IP and raises no alert."""
    ok, user, _ = authenticate_user("test_admin", "AdminPass123", ip_address="10.0.0.5", db_path=populated_db)
    assert ok is True
    assert user["login_ip"] == "10.0.0.5"
    assert user["ip_alert"] is None
    assert get_known_ips("U_ADM", db_path=populated_db) == ["10.0.0.5"]

    logs = get_audit_logs(event_type="LOGIN_IP_REGISTERED", db_path=populated_db)
    assert len(logs) == 1
    assert logs[0]["ip_address"] == "10.0.0.5"


def test_same_ip_login_not_flagged(populated_db):
    """Logging in again from a known IP is recorded but not flagged."""
    authenticate_user("test_viewer", "ViewerPass123", ip_address="10.0.0.5", db_path=populated_db)
    ok, user, _ = authenticate_user("test_viewer", "ViewerPass123", ip_address="10.0.0.5", db_path=populated_db)
    assert ok is True
    assert user["ip_alert"] is None
    assert len(get_login_history(user_id="U_VIE", db_path=populated_db)) == 2
    assert get_login_history(only_new_ip=True, db_path=populated_db) == []


def test_new_ip_login_allowed_but_flagged(populated_db):
    """A login from a different IP is allowed, stored, and flagged with an alert."""
    authenticate_user("test_admin", "AdminPass123", ip_address="10.0.0.5", db_path=populated_db)
    ok, user, err = authenticate_user("test_admin", "AdminPass123", ip_address="192.168.1.77", db_path=populated_db)

    assert ok is True
    assert err is None
    assert user["login_ip"] == "192.168.1.77"
    assert user["ip_alert"] == {"new_ip": "192.168.1.77", "known_ips": ["10.0.0.5"]}

    flagged = get_login_history(only_new_ip=True, db_path=populated_db)
    assert len(flagged) == 1
    assert flagged[0]["ip_address"] == "192.168.1.77"
    assert flagged[0]["known_ips"] == "10.0.0.5"

    alerts = get_audit_logs(event_type="NEW_IP_LOGIN", db_path=populated_db)
    assert len(alerts) == 1
    assert alerts[0]["status"] == "ALERT"
    assert alerts[0]["ip_address"] == "192.168.1.77"
    assert get_system_metrics(populated_db)["new_ip_alerts"] == 1

    # Once seen, the new IP becomes known and is not flagged again
    _, again, _ = authenticate_user("test_admin", "AdminPass123", ip_address="192.168.1.77", db_path=populated_db)
    assert again["ip_alert"] is None


def test_failed_login_does_not_register_ip(populated_db):
    """Wrong passwords record the IP in the audit log but never register it as known."""
    ok, _, _ = authenticate_user("test_admin", "wrong", ip_address="203.0.113.9", db_path=populated_db)
    assert ok is False
    assert get_known_ips("U_ADM", db_path=populated_db) == []

    failed = get_audit_logs(event_type="LOGIN_FAILED", db_path=populated_db)
    assert failed[0]["ip_address"] == "203.0.113.9"


def test_detection_disabled_records_without_alert(populated_db):
    """With detection turned off, IPs are still stored but nothing is flagged."""
    authenticate_user("test_researcher", "ResearchPass123", ip_address="10.0.0.5", db_path=populated_db)
    _, user, _ = authenticate_user(
        "test_researcher", "ResearchPass123", ip_address="10.0.0.6", db_path=populated_db, detect_new_ip=False
    )
    assert user["ip_alert"] is None
    assert len(get_login_history(user_id="U_RES", db_path=populated_db)) == 2
    assert get_login_history(only_new_ip=True, db_path=populated_db) == []


def test_security_log_file_written(populated_db):
    """Security events are appended to the plain-text log file with the IP address."""
    log_path = get_security_log_path(populated_db)
    if log_path.exists():
        log_path.unlink()
    try:
        authenticate_user("test_admin", "AdminPass123", ip_address="10.0.0.5", db_path=populated_db)
        authenticate_user("test_admin", "AdminPass123", ip_address="172.16.0.9", db_path=populated_db)

        content = log_path.read_text(encoding="utf-8")
        assert "NEW_IP_LOGIN" in content
        assert "ip=172.16.0.9" in content
        assert "AdminPass123" not in content
    finally:
        if log_path.exists():
            log_path.unlink()
