"""
Unit Tests for Simulated AI Service and Execution Authorization.
"""

import pytest
from ai_service import execute_ai_research_task, analyze_text_deterministic
from permissions import Role
from database import get_audit_logs, get_ai_experiments
from audit import AuditEvent


def test_deterministic_text_analysis():
    """Verify deterministic NLP keyword extraction, sentiment, and PII detection."""
    sample = "The machine learning algorithm achieved optimal accuracy. Contact researcher at test@ai.org or 555-123-4567."
    res = analyze_text_deterministic(sample, max_keywords=3)

    assert res["word_count"] > 10
    assert len(res["keywords"]) <= 3
    assert res["sentiment"] == "Positive"
    assert len(res["pii_detected"]) == 2  # email and phone detected


def test_researcher_ai_execution_authorized(populated_db):
    """Test that a Researcher role can execute AI research pipeline."""
    researcher = {"user_id": "U_RES", "username": "test_researcher", "role": Role.RESEARCHER.value}
    
    res = execute_ai_research_task(
        user=researcher,
        input_text="Testing simulated AI pipeline for research evaluation.",
        db_path=populated_db
    )

    assert "word_count" in res
    assert res["word_count"] > 0

    # Verify persisted in database
    experiments = get_ai_experiments(db_path=populated_db)
    assert len(experiments) == 1
    assert experiments[0]["username"] == "test_researcher"

    # Verify audit event
    logs = get_audit_logs(event_type=AuditEvent.AI_TASK_EXECUTED.value, db_path=populated_db)
    assert len(logs) == 1


def test_admin_ai_execution_authorized(populated_db):
    """Test that an Admin role can also execute AI pipeline."""
    admin = {"user_id": "U_ADM", "username": "test_admin", "role": Role.ADMIN.value}
    
    res = execute_ai_research_task(
        user=admin,
        input_text="Admin testing pipeline access.",
        db_path=populated_db
    )
    assert res["word_count"] > 0


def test_viewer_ai_execution_denied(populated_db):
    """Test that a Viewer role is strictly blocked from executing AI pipeline."""
    viewer = {"user_id": "U_VIE", "username": "test_viewer", "role": Role.VIEWER.value}

    with pytest.raises(PermissionError) as exc_info:
        execute_ai_research_task(
            user=viewer,
            input_text="Unauthorized execution attempt by viewer.",
            db_path=populated_db
        )

    assert "Access Denied" in str(exc_info.value)

    # Verify security denial was logged to audit table
    logs = get_audit_logs(event_type=AuditEvent.AI_TASK_DENIED.value, db_path=populated_db)
    assert len(logs) == 1
    assert logs[0]["username"] == "test_viewer"
