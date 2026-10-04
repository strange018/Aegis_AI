"""
Unit and Integration Tests for Authentication and User Management.
"""

import pytest
from auth import (
    hash_password,
    verify_password,
    authenticate_user,
    admin_create_user,
    admin_change_role,
    admin_toggle_status,
)
from database import get_user_by_username
from permissions import Role


def test_password_hashing_and_verification():
    """Verify that Werkzeug produces secure hashes and verifies correctly."""
    plain = "MySecretPass@123"
    hashed = hash_password(plain)

    assert hashed != plain
    assert hashed.startswith("scrypt:") or hashed.startswith("pbkdf2:")
    assert verify_password(hashed, plain) is True
    assert verify_password(hashed, "WrongPassword") is False
    assert verify_password(hashed, "") is False


def test_successful_login(populated_db):
    """Test successful authentication with valid credentials."""
    success, user, err = authenticate_user("test_admin", "AdminPass123", db_path=populated_db)
    assert success is True
    assert err is None
    assert user is not None
    assert user["username"] == "test_admin"
    assert user["role"] == Role.ADMIN.value
    assert "password_hash" not in user  # Ensure hash is never exposed in user dict


def test_failed_login_wrong_password(populated_db):
    """Test failed authentication with incorrect password."""
    success, user, err = authenticate_user("test_admin", "WrongPass!", db_path=populated_db)
    assert success is False
    assert user is None
    assert err == "Invalid username or password."


def test_failed_login_nonexistent_user(populated_db):
    """Test failed login with non-existent username returns generic error."""
    success, user, err = authenticate_user("ghost_user", "SomePass", db_path=populated_db)
    assert success is False
    assert user is None
    assert err == "Invalid username or password."


def test_inactive_account_login_denial(populated_db):
    """Test that deactivated accounts cannot log in."""
    success, user, err = authenticate_user("test_inactive", "InactivePass123", db_path=populated_db)
    assert success is False
    assert user is None
    assert "deactivated" in err.lower()


def test_admin_create_user_authorized(populated_db):
    """Test that an admin can create new users."""
    admin_actor = {"user_id": "U_ADM", "username": "test_admin", "role": Role.ADMIN.value}
    
    ok, msg = admin_create_user(
        acting_user=admin_actor,
        user_id="U_NEW",
        username="new_user",
        password="ValidPassword123",
        role=Role.RESEARCHER.value,
        is_active=True,
        db_path=populated_db
    )
    assert ok is True
    assert "created successfully" in msg

    created = get_user_by_username("new_user", db_path=populated_db)
    assert created is not None
    assert created["role"] == Role.RESEARCHER.value


def test_admin_create_user_unauthorized(populated_db):
    """Test that researchers and viewers CANNOT create users (Least Privilege)."""
    researcher_actor = {"user_id": "U_RES", "username": "test_researcher", "role": Role.RESEARCHER.value}
    
    ok, msg = admin_create_user(
        acting_user=researcher_actor,
        user_id="U_FAIL",
        username="fail_user",
        password="ValidPassword123",
        role=Role.VIEWER.value,
        is_active=True,
        db_path=populated_db
    )
    assert ok is False
    assert "Access Denied" in msg

    # Ensure user was not created in DB
    assert get_user_by_username("fail_user", db_path=populated_db) is None


def test_admin_role_change(populated_db):
    """Test updating user role by an admin."""
    admin_actor = {"user_id": "U_ADM", "username": "test_admin", "role": Role.ADMIN.value}
    
    ok, msg = admin_change_role(
        acting_user=admin_actor,
        target_user_id="U_VIE",
        new_role=Role.RESEARCHER.value,
        db_path=populated_db
    )
    assert ok is True

    user = get_user_by_username("test_viewer", db_path=populated_db)
    assert user["role"] == Role.RESEARCHER.value


def test_admin_prevent_self_deactivation(populated_db):
    """Test safety guard against admin deactivating own account."""
    admin_actor = {"user_id": "U_ADM", "username": "test_admin", "role": Role.ADMIN.value}
    
    ok, msg = admin_toggle_status(
        acting_user=admin_actor,
        target_user_id="U_ADM",
        activate=False,
        db_path=populated_db
    )
    assert ok is False
    assert "Self-deactivation is prevented" in msg
