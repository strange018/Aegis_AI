"""
Authentication and Authorization Module for RBAC AI Platform.

Handles secure password hashing (Werkzeug), user verification, session state management,
and fine-grained server-side permission validation.
"""

from typing import Optional, Tuple, Dict, Any
from werkzeug.security import generate_password_hash, check_password_hash
import streamlit as st

from database import (
    get_user_by_username,
    get_user_by_id,
    insert_user,
    update_user_role,
    set_user_active_status,
    update_user_password,
    get_all_users,
    count_users,
    get_known_ips,
    insert_login_record,
)
from permissions import Role, Permission, has_permission, get_role_permissions
from audit import log_event, AuditEvent
from network import get_client_ip
import config


# ==========================================
# Password Hashing Functions
# ==========================================

def hash_password(plain_password: str) -> str:
    """
    Generate secure password hash using Werkzeug's default modern hashing algorithm (scrypt/pbkdf2).
    """
    if not plain_password:
        raise ValueError("Password cannot be empty.")
    return generate_password_hash(plain_password)


def verify_password(stored_hash: str, plain_password: str) -> bool:
    """
    Verifies a plain-text password against a stored Werkzeug hash.
    Constant-time comparison prevents timing attacks.
    """
    if not stored_hash or not plain_password:
        return False
    return check_password_hash(stored_hash, plain_password)


# ==========================================
# Core Authentication
# ==========================================

def authenticate_user(
    username: str,
    password: str,
    ip_address: Optional[str] = None,
    db_path: Optional[str] = None,
    detect_new_ip: Optional[bool] = None
) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
    """
    Authenticates a user against SQLite credentials.
    Enforces active account status and logs all successful and failed attempts.
    Every successful login stores the client IP in `login_history`; a login from an IP
    the user has never used before is allowed but flagged (NEW_IP_LOGIN alert).
    Returns: (is_authenticated, user_dict_without_hash, error_message)
    """
    if not ip_address:
        ip_address = get_client_ip()
    if detect_new_ip is None:
        detect_new_ip = config.IP_ANOMALY_DETECTION

    clean_username = username.strip().lower() if username else ""
    if not clean_username or not password:
        return False, None, "Please provide both username and password."

    user = get_user_by_username(clean_username, db_path=db_path)
    
    if not user:
        # User not found: log generic failure (avoid username enumeration)
        log_event(
            AuditEvent.LOGIN_FAILED,
            f"Failed login attempt for non-existent username: '{clean_username}'",
            status="FAILURE",
            ip_address=ip_address,
            db_path=db_path
        )
        return False, None, "Invalid username or password."

    # Check password match
    if not verify_password(user["password_hash"], password):
        log_event(
            AuditEvent.LOGIN_FAILED,
            f"Invalid password entered for user '{clean_username}'",
            user_id=user["user_id"],
            username=user["username"],
            status="FAILURE",
            ip_address=ip_address,
            db_path=db_path
        )
        return False, None, "Invalid username or password."

    # Check active status
    if not user["is_active"]:
        log_event(
            AuditEvent.ACCOUNT_LOCKED,
            f"Deactivated user '{clean_username}' attempted to log in",
            user_id=user["user_id"],
            username=user["username"],
            status="BLOCKED",
            ip_address=ip_address,
            db_path=db_path
        )
        return False, None, "Your account is currently deactivated. Please contact an administrator."

    # Successful authentication
    log_event(
        AuditEvent.LOGIN_SUCCESS,
        f"User '{clean_username}' successfully authenticated with role '{user['role']}'",
        user_id=user["user_id"],
        username=user["username"],
        status="SUCCESS",
        ip_address=ip_address,
        db_path=db_path
    )

    # Login IP check: compare against every IP this user has logged in from before
    ip_alert = check_login_ip(user, ip_address, detect_new_ip=detect_new_ip, db_path=db_path)

    # Return safe user dictionary (without password_hash)
    safe_user = {
        "user_id": user["user_id"],
        "username": user["username"],
        "role": user["role"],
        "is_active": bool(user["is_active"]),
        "created_at": user["created_at"],
        "permissions": list(get_role_permissions(user["role"])),
        "login_ip": ip_address,
        "ip_alert": ip_alert
    }
    return True, safe_user, None


def check_login_ip(
    user: Dict[str, Any],
    ip_address: str,
    detect_new_ip: bool = True,
    db_path: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """
    Records the login IP and decides whether it is anomalous.

    - First ever login: the IP is registered as the user's known IP (LOGIN_IP_REGISTERED).
    - Login from an already known IP: recorded, no alert.
    - Login from a new IP: recorded, allowed, and flagged with a NEW_IP_LOGIN alert.

    Returns an alert dict for a flagged login, otherwise None.
    """
    known_ips = get_known_ips(user["user_id"], db_path=db_path)
    is_first_login = not known_ips
    is_new_ip = detect_new_ip and not is_first_login and ip_address not in known_ips

    insert_login_record(
        user_id=user["user_id"],
        username=user["username"],
        role=user["role"],
        ip_address=ip_address,
        is_new_ip=is_new_ip,
        known_ips=known_ips,
        db_path=db_path
    )

    if is_first_login:
        log_event(
            AuditEvent.LOGIN_IP_REGISTERED,
            f"First login of '{user['username']}' recorded from IP {ip_address}; registered as known IP",
            user_id=user["user_id"],
            username=user["username"],
            status="SUCCESS",
            ip_address=ip_address,
            db_path=db_path
        )
        return None

    if not is_new_ip:
        return None

    log_event(
        AuditEvent.NEW_IP_LOGIN,
        f"ALERT: '{user['username']}' (role '{user['role']}') logged in from new IP {ip_address}. "
        f"Previously known IPs: {', '.join(known_ips)}",
        user_id=user["user_id"],
        username=user["username"],
        status="ALERT",
        ip_address=ip_address,
        db_path=db_path
    )
    return {"new_ip": ip_address, "known_ips": known_ips}


# ==========================================
# Administrator User Management Operations
# ==========================================

def admin_create_user(
    acting_user: Dict[str, Any],
    user_id: str,
    username: str,
    password: str,
    role: str,
    is_active: bool = True,
    db_path: Optional[str] = None
) -> Tuple[bool, str]:
    """
    Creates a new user account. Restricted to administrators.
    """
    if not has_permission(acting_user.get("role", ""), Permission.MANAGE_USERS.value):
        log_event(
            AuditEvent.PRIVILEGE_ESCALATION_BLOCKED,
            f"Unauthorized user '{acting_user.get('username')}' attempted to create a user",
            user_id=acting_user.get("user_id"),
            username=acting_user.get("username"),
            status="DENIED",
            db_path=db_path
        )
        return False, "Access Denied: You lack permissions to create users."

    if not Role.is_valid(role):
        return False, f"Invalid role '{role}'. Valid roles are: {Role.valid_roles()}"

    if len(password) < 6:
        return False, "Password must be at least 6 characters long."

    existing = get_user_by_username(username, db_path=db_path)
    if existing:
        return False, f"Username '{username}' already exists."

    existing_id = get_user_by_id(user_id, db_path=db_path)
    if existing_id:
        return False, f"User ID '{user_id}' already exists."

    pwd_hash = hash_password(password)
    insert_user(user_id, username, pwd_hash, role, 1 if is_active else 0, db_path=db_path)

    log_event(
        AuditEvent.USER_CREATED,
        f"Admin '{acting_user.get('username')}' created new user '{username}' with role '{role}'",
        user_id=acting_user.get("user_id"),
        username=acting_user.get("username"),
        status="SUCCESS",
        db_path=db_path
    )
    return True, f"User '{username}' created successfully."


def admin_change_role(
    acting_user: Dict[str, Any],
    target_user_id: str,
    new_role: str,
    db_path: Optional[str] = None
) -> Tuple[bool, str]:
    """
    Changes a target user's role. Restricted to administrators.
    """
    if not has_permission(acting_user.get("role", ""), Permission.ASSIGN_ROLES.value):
        log_event(
            AuditEvent.PRIVILEGE_ESCALATION_BLOCKED,
            f"User '{acting_user.get('username')}' attempted unauthorized role modification",
            user_id=acting_user.get("user_id"),
            username=acting_user.get("username"),
            status="DENIED",
            db_path=db_path
        )
        return False, "Access Denied: You do not have permission to assign roles."

    if not Role.is_valid(new_role):
        return False, f"Invalid role '{new_role}'."

    target = get_user_by_id(target_user_id, db_path=db_path)
    if not target:
        return False, "Target user not found."

    old_role = target["role"]
    update_user_role(target_user_id, new_role, db_path=db_path)

    log_event(
        AuditEvent.USER_ROLE_CHANGED,
        f"Admin '{acting_user.get('username')}' changed role of '{target['username']}' from '{old_role}' to '{new_role}'",
        user_id=acting_user.get("user_id"),
        username=acting_user.get("username"),
        status="SUCCESS",
        db_path=db_path
    )
    return True, f"Role for '{target['username']}' updated to '{new_role}'."


def admin_toggle_status(
    acting_user: Dict[str, Any],
    target_user_id: str,
    activate: bool,
    db_path: Optional[str] = None
) -> Tuple[bool, str]:
    """
    Activates or deactivates an account. Prevents an admin from deactivating themselves.
    """
    if not has_permission(acting_user.get("role", ""), Permission.MANAGE_USERS.value):
        log_event(
            AuditEvent.PRIVILEGE_ESCALATION_BLOCKED,
            f"User '{acting_user.get('username')}' attempted unauthorized account status modification",
            user_id=acting_user.get("user_id"),
            username=acting_user.get("username"),
            status="DENIED",
            db_path=db_path
        )
        return False, "Access Denied."

    if acting_user.get("user_id") == target_user_id and not activate:
        return False, "Self-deactivation is prevented for administrative safety."

    target = get_user_by_id(target_user_id, db_path=db_path)
    if not target:
        return False, "Target user not found."

    set_user_active_status(target_user_id, activate, db_path=db_path)
    event_type = AuditEvent.USER_ACTIVATED if activate else AuditEvent.USER_DEACTIVATED
    action_str = "activated" if activate else "deactivated"

    log_event(
        event_type,
        f"Admin '{acting_user.get('username')}' {action_str} user '{target['username']}'",
        user_id=acting_user.get("user_id"),
        username=acting_user.get("username"),
        status="SUCCESS",
        db_path=db_path
    )
    return True, f"User '{target['username']}' {action_str}."


def admin_reset_password(
    acting_user: Dict[str, Any],
    target_user_id: str,
    new_password: str,
    db_path: Optional[str] = None
) -> Tuple[bool, str]:
    """
    Resets a user's password. Restricted to administrators.
    """
    if not has_permission(acting_user.get("role", ""), Permission.MANAGE_USERS.value):
        return False, "Access Denied."

    if len(new_password) < 6:
        return False, "Password must be at least 6 characters long."

    target = get_user_by_id(target_user_id, db_path=db_path)
    if not target:
        return False, "Target user not found."

    pwd_hash = hash_password(new_password)
    update_user_password(target_user_id, pwd_hash, db_path=db_path)

    log_event(
        AuditEvent.PASSWORD_RESET,
        f"Admin '{acting_user.get('username')}' reset password for user '{target['username']}'",
        user_id=acting_user.get("user_id"),
        username=acting_user.get("username"),
        status="SUCCESS",
        db_path=db_path
    )
    return True, f"Password for '{target['username']}' has been reset."


# ==========================================
# Streamlit Session Helpers
# ==========================================

def init_session() -> None:
    """Initialize Streamlit session state keys if not already set."""
    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False
    if "user" not in st.session_state:
        st.session_state.user = None
    if "nav_page" not in st.session_state:
        st.session_state.nav_page = "Dashboard"


def get_current_user() -> Optional[Dict[str, Any]]:
    """Get the currently logged-in user dict from session state."""
    if st.session_state.get("authenticated", False):
        return st.session_state.get("user")
    return None


def is_authenticated() -> bool:
    """Check if a session is actively authenticated."""
    return bool(st.session_state.get("authenticated", False))


def login_session(user_dict: Dict[str, Any]) -> None:
    """Set authenticated session state."""
    st.session_state.authenticated = True
    st.session_state.user = user_dict
    st.session_state.nav_page = "Dashboard"


def logout_session() -> None:
    """Log out and clear session state."""
    user = st.session_state.get("user")
    if user:
        log_event(
            AuditEvent.LOGOUT,
            f"User '{user.get('username')}' logged out",
            user_id=user.get("user_id"),
            username=user.get("username"),
            status="SUCCESS",
            ip_address=user.get("login_ip")
        )
    st.session_state.authenticated = False
    st.session_state.user = None
    st.session_state.nav_page = "Login"
