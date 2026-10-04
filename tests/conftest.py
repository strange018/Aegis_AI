"""
Pytest configuration and fixtures for RBAC AI Platform.
Creates isolated temporary databases for test isolation.
"""

import sys
import os
from pathlib import Path
import tempfile
import pytest

# Add parent directory to python path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from database import init_db, insert_user
from auth import hash_password
from permissions import Role


@pytest.fixture
def temp_db():
    """Provides a fresh, temporary SQLite database for each test."""
    temp_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    temp_file.close()
    db_path = temp_file.name

    init_db(db_path)

    yield db_path

    # Cleanup after test
    if os.path.exists(db_path):
        try:
            os.remove(db_path)
        except PermissionError:
            pass


@pytest.fixture
def populated_db(temp_db):
    """Provides a database populated with test admin, researcher, viewer, and inactive user."""
    # 1. Admin
    insert_user(
        user_id="U_ADM",
        username="test_admin",
        password_hash=hash_password("AdminPass123"),
        role=Role.ADMIN.value,
        is_active=1,
        db_path=temp_db
    )

    # 2. Researcher
    insert_user(
        user_id="U_RES",
        username="test_researcher",
        password_hash=hash_password("ResearchPass123"),
        role=Role.RESEARCHER.value,
        is_active=1,
        db_path=temp_db
    )

    # 3. Viewer
    insert_user(
        user_id="U_VIE",
        username="test_viewer",
        password_hash=hash_password("ViewerPass123"),
        role=Role.VIEWER.value,
        is_active=1,
        db_path=temp_db
    )

    # 4. Inactive Account
    insert_user(
        user_id="U_INA",
        username="test_inactive",
        password_hash=hash_password("InactivePass123"),
        role=Role.VIEWER.value,
        is_active=0,
        db_path=temp_db
    )

    return temp_db
