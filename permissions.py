"""
Role-Based Access Control (RBAC) Permission Definitions and Server-Side Policy.

This module defines the central security policy for the AI Platform.
All role permissions are enforced server-side. The untrusted 'permissions'
column from external CSV inputs is strictly validated against this policy.
"""

from enum import Enum
from typing import List, Dict, Set, Optional


class Role(str, Enum):
    """Supported user roles in the system."""
    ADMIN = "admin"
    RESEARCHER = "researcher"
    VIEWER = "viewer"

    @classmethod
    def valid_roles(cls) -> List[str]:
        return [role.value for role in cls]

    @classmethod
    def is_valid(cls, role_str: str) -> bool:
        return role_str.strip().lower() in cls.valid_roles()


class Permission(str, Enum):
    """System-level atomic permissions following the Principle of Least Privilege."""
    MANAGE_USERS = "manage_users"          # Create, edit, activate/deactivate users
    ASSIGN_ROLES = "assign_roles"          # Change user roles
    VIEW_AUDIT_LOGS = "view_audit_logs"    # Access security audit logs
    SYSTEM_CONFIG = "system_config"        # Import CSV, manage DB, view system stats
    RUN_AI = "run_ai"                      # Execute simulated AI models and text analysis
    VIEW_RESULTS = "view_results"          # View public/shared AI research benchmarks
    VIEW_SYSTEM_STATS = "view_system_stats"# View aggregate user & system metrics


# Centralized Role-to-Permission Mapping (Server-side Single Source of Truth)
ROLE_PERMISSIONS: Dict[Role, Set[Permission]] = {
    Role.ADMIN: {
        Permission.MANAGE_USERS,
        Permission.ASSIGN_ROLES,
        Permission.VIEW_AUDIT_LOGS,
        Permission.SYSTEM_CONFIG,
        Permission.RUN_AI,
        Permission.VIEW_RESULTS,
        Permission.VIEW_SYSTEM_STATS,
    },
    Role.RESEARCHER: {
        Permission.RUN_AI,
        Permission.VIEW_RESULTS,
        Permission.VIEW_SYSTEM_STATS,
    },
    Role.VIEWER: {
        Permission.VIEW_RESULTS,
        Permission.VIEW_SYSTEM_STATS,
    },
}

# Role Hierarchical Descriptions for UI & Reports
ROLE_DESCRIPTIONS = {
    Role.ADMIN.value: "Full administrative access: user management, role assignments, system imports, and audit log inspection.",
    Role.RESEARCHER.value: "Operational research access: execute simulated AI pipelines, analyze inputs, and export test results.",
    Role.VIEWER.value: "Read-only access: view non-sensitive system summaries and published AI model benchmark reports.",
}


def get_role_permissions(role: str) -> Set[str]:
    """
    Returns the set of permission strings strictly granted to the given role.
    If the role is invalid or unknown, an empty set is returned (fail-secure).
    """
    if not role:
        return set()
    role_str = role.strip().lower()
    for r, perms in ROLE_PERMISSIONS.items():
        if r.value == role_str:
            return {p.value for p in perms}
    return set()


def has_permission(role: str, permission: str) -> bool:
    """
    Server-side authorization check.
    Validates whether the specified role has the requested atomic permission.
    """
    if not role or not permission:
        return False
    perms = get_role_permissions(role)
    return permission in perms


def can_access_page(role: str, page_name: str) -> bool:
    """
    Evaluates whether a role is authorized to access a given UI view/dashboard.
    """
    role = role.strip().lower() if role else ""
    page = page_name.strip().lower()

    if page in ["overview", "viewer_dashboard", "public_benchmarks"]:
        return has_permission(role, Permission.VIEW_RESULTS.value)
    elif page in ["researcher_dashboard", "ai_workspace", "ai_simulator"]:
        return has_permission(role, Permission.RUN_AI.value)
    elif page in ["admin_dashboard", "user_management", "audit_logs", "csv_import", "system_settings"]:
        return has_permission(role, Permission.MANAGE_USERS.value)
    return False
