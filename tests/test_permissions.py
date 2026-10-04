"""
Unit Tests for Role-Based Access Control and Server-Side Permissions.
"""

from permissions import Role, Permission, has_permission, get_role_permissions, can_access_page


def test_admin_permissions():
    """Verify Admin role has all management, AI execution, and audit permissions."""
    admin_perms = get_role_permissions(Role.ADMIN.value)
    
    assert Permission.MANAGE_USERS.value in admin_perms
    assert Permission.ASSIGN_ROLES.value in admin_perms
    assert Permission.VIEW_AUDIT_LOGS.value in admin_perms
    assert Permission.SYSTEM_CONFIG.value in admin_perms
    assert Permission.RUN_AI.value in admin_perms
    assert Permission.VIEW_RESULTS.value in admin_perms


def test_researcher_least_privilege():
    """Verify Researcher has AI execution and result viewing, but NO admin or audit capabilities."""
    res_perms = get_role_permissions(Role.RESEARCHER.value)
    
    assert Permission.RUN_AI.value in res_perms
    assert Permission.VIEW_RESULTS.value in res_perms
    
    # Must NOT have administrative privileges
    assert Permission.MANAGE_USERS.value not in res_perms
    assert Permission.ASSIGN_ROLES.value not in res_perms
    assert Permission.VIEW_AUDIT_LOGS.value not in res_perms
    assert Permission.SYSTEM_CONFIG.value not in res_perms


def test_viewer_least_privilege():
    """Verify Viewer has read-only permissions and cannot run AI or manage users."""
    view_perms = get_role_permissions(Role.VIEWER.value)
    
    assert Permission.VIEW_RESULTS.value in view_perms
    assert Permission.VIEW_SYSTEM_STATS.value in view_perms
    
    # Must NOT have execution or admin privileges
    assert Permission.RUN_AI.value not in view_perms
    assert Permission.MANAGE_USERS.value not in view_perms
    assert Permission.VIEW_AUDIT_LOGS.value not in view_perms


def test_invalid_role_fail_secure():
    """Verify that unknown/tampered roles return zero permissions (fail-secure design)."""
    assert get_role_permissions("super_admin_bypass") == set()
    assert has_permission("hacker_role", Permission.RUN_AI.value) is False
    assert has_permission("", Permission.VIEW_RESULTS.value) is False
    assert has_permission(None, Permission.VIEW_RESULTS.value) is False


def test_page_routing_access_matrix():
    """Test UI page access permissions."""
    # Admin
    assert can_access_page(Role.ADMIN.value, "admin_dashboard") is True
    assert can_access_page(Role.ADMIN.value, "audit_logs") is True
    assert can_access_page(Role.ADMIN.value, "ai_workspace") is True
    assert can_access_page(Role.ADMIN.value, "public_benchmarks") is True

    # Researcher
    assert can_access_page(Role.RESEARCHER.value, "ai_workspace") is True
    assert can_access_page(Role.RESEARCHER.value, "public_benchmarks") is True
    assert can_access_page(Role.RESEARCHER.value, "admin_dashboard") is False
    assert can_access_page(Role.RESEARCHER.value, "audit_logs") is False

    # Viewer
    assert can_access_page(Role.VIEWER.value, "public_benchmarks") is True
    assert can_access_page(Role.VIEWER.value, "ai_workspace") is False
    assert can_access_page(Role.VIEWER.value, "admin_dashboard") is False
    assert can_access_page(Role.VIEWER.value, "audit_logs") is False
