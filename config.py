import os
from pathlib import Path
from dotenv import load_dotenv

# Base Directory
BASE_DIR = Path(__file__).resolve().parent

# Load .env if present
load_dotenv(BASE_DIR / ".env")

# Database Configuration
DEFAULT_DB_PATH = os.getenv("DB_PATH", str(BASE_DIR / "rbac_platform.db"))

# Default Setup Credentials (used only during initial bootstrapping if database is empty)
DEFAULT_ADMIN_USERNAME = os.getenv("DEFAULT_ADMIN_USERNAME", "admin")
DEFAULT_ADMIN_PASSWORD = os.getenv("DEFAULT_ADMIN_PASSWORD", "Admin@Secure2026")
DEFAULT_USER_PASSWORD = os.getenv("DEFAULT_USER_PASSWORD", "User@Secure2026")

# Login IP Security
# When true, a successful login from an IP address the user has never used before
# is allowed but flagged with an alert (audit log, security.log and admin dashboard).
IP_ANOMALY_DETECTION = os.getenv("IP_ANOMALY_DETECTION", "true").strip().lower() in ("1", "true", "yes", "on")

# Plain-text security log file (written next to the database)
SECURITY_LOG_FILENAME = os.getenv("SECURITY_LOG_FILENAME", "security.log")

# Application Settings
APP_NAME = "Aegis AI Platform"
APP_VERSION = "1.0.0"
