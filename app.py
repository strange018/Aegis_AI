"""
Streamlit Web Application: Role-Based Access Control (RBAC) for AI Platform.

Demonstrates authentication, authorization, principle of least privilege,
secure password management, CSV import validation, audit logging, and
deterministic AI research features.
"""

import os
import json
from pathlib import Path
import streamlit as st
import pandas as pd
from datetime import datetime

from config import (
    APP_NAME,
    APP_VERSION,
    DEFAULT_DB_PATH,
    DEFAULT_ADMIN_USERNAME,
    DEFAULT_ADMIN_PASSWORD,
    DEFAULT_USER_PASSWORD,
)
from database import (
    init_db,
    get_all_users,
    get_audit_logs,
    get_system_metrics,
    get_ai_experiments,
    count_users,
    get_user_by_username,
    insert_user,
    get_login_history,
    get_user_ip_summary,
)
from permissions import Role, Permission, has_permission, get_role_permissions, ROLE_DESCRIPTIONS
from auth import (
    init_session,
    get_current_user,
    is_authenticated,
    login_session,
    logout_session,
    authenticate_user,
    admin_create_user,
    admin_change_role,
    admin_toggle_status,
    admin_reset_password,
    hash_password,
)
from import_users import import_users_from_csv
from ai_service import execute_ai_research_task
from audit import log_event, AuditEvent, get_security_log_path
from network import get_client_ip


# Page Configuration
st.set_page_config(
    page_title="Aegis AI - Enterprise RBAC Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Initialize Database Schema & Streamlit Session
init_db(DEFAULT_DB_PATH)
init_session()

# Auto-seed admin and dataset on clean start (essential for zero-configuration cloud deployment)
if count_users(DEFAULT_DB_PATH) == 0:
    admin_hash = hash_password(DEFAULT_ADMIN_PASSWORD)
    insert_user("ADMIN001", DEFAULT_ADMIN_USERNAME, admin_hash, Role.ADMIN.value, 1, db_path=DEFAULT_DB_PATH)
    csv_file = Path(__file__).resolve().parent / "users.csv"
    if csv_file.exists():
        import_users_from_csv(str(csv_file), default_password=DEFAULT_USER_PASSWORD, db_path=DEFAULT_DB_PATH)


# ==========================================
# Luxury Nodal-Inspired Theme & Design Tokens
# ==========================================
NODAL_CUSTOM_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Cinzel:wght@500;700&family=Inter:wght@300;400;500;600;700&family=Newsreader:ital,opsz,wght@0,6..72,400;0,6..72,500;0,6..72,600;1,6..72,400&family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap');

/* Root Variables */
:root {
    --bg-dark: #0c0507;
    --bg-crimson-deep: #20050d;
    --bg-crimson-mid: #520c1d;
    --bg-crimson-bright: #941733;
    --bg-crimson-glow: #bd284a;
    --mint-accent: #6ee7b7;
    --mint-hover: #a7f3d0;
    --mint-text: #064e3b;
    --text-primary: #ffffff;
    --text-secondary: #e2cad1;
    --text-muted: #a8848f;
    --card-bg: rgba(26, 6, 13, 0.72);
    --card-border: rgba(255, 120, 150, 0.16);
    --card-glow: rgba(189, 40, 74, 0.25);
    --glass-blur: blur(18px);
}

/* Global Background with Atmospheric Crimson & Grid Overlay */
.stApp {
    background-color: var(--bg-dark);
    background-image: 
        radial-gradient(circle at 50% 90%, rgba(220, 38, 76, 0.45) 0%, rgba(148, 23, 51, 0.3) 35%, rgba(32, 5, 13, 0.8) 70%, #0c0507 100%),
        radial-gradient(rgba(255, 255, 255, 0.08) 1px, transparent 1px),
        linear-gradient(180deg, rgba(12, 5, 7, 0.95) 0%, rgba(35, 7, 16, 0.85) 45%, rgba(85, 14, 32, 0.75) 100%);
    background-size: 100% 100%, 28px 28px, 100% 100%;
    background-attachment: fixed;
    color: var(--text-primary);
    font-family: 'Plus Jakarta Sans', 'Inter', -apple-system, sans-serif;
}

/* Custom Scrollbar */
::-webkit-scrollbar {
    width: 8px;
    height: 8px;
}
::-webkit-scrollbar-track {
    background: #120408;
}
::-webkit-scrollbar-thumb {
    background: #611024;
    border-radius: 4px;
}
::-webkit-scrollbar-thumb:hover {
    background: var(--bg-crimson-glow);
}

/* Header & Typography */
h1, h2, h3 {
    color: #ffffff !important;
    font-family: 'Newsreader', 'Cinzel', serif !important;
    font-weight: 500 !important;
    letter-spacing: -0.02em;
}

.hero-title {
    font-family: 'Newsreader', serif;
    font-size: 3.2rem;
    font-weight: 400;
    line-height: 1.15;
    text-align: center;
    color: #ffffff;
    margin: 15px 0 10px 0;
    letter-spacing: -0.03em;
}

.hero-subtitle {
    font-family: 'Plus Jakarta Sans', sans-serif;
    font-size: 1.05rem;
    color: var(--text-secondary);
    text-align: center;
    max-width: 720px;
    margin: 0 auto 30px auto;
    line-height: 1.6;
    font-weight: 300;
}

.pill-badge {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    background: rgba(255, 255, 255, 0.07);
    border: 1px solid rgba(255, 255, 255, 0.15);
    padding: 6px 16px;
    border-radius: 9999px;
    font-size: 0.82rem;
    color: var(--text-secondary);
    letter-spacing: 0.02em;
    backdrop-filter: blur(10px);
    margin: 0 auto;
}

/* Top Navigation Bar Simulation */
.nodal-nav {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 16px 28px;
    border-bottom: 1px solid rgba(255, 255, 255, 0.08);
    background: rgba(15, 4, 8, 0.7);
    backdrop-filter: blur(20px);
    border-radius: 18px;
    margin-bottom: 28px;
}
.nodal-brand {
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 1.25rem;
    font-weight: 700;
    color: #ffffff;
    letter-spacing: -0.01em;
}
.nodal-links {
    display: flex;
    gap: 28px;
    color: var(--text-muted);
    font-size: 0.9rem;
    font-weight: 500;
}
.nodal-links span:hover {
    color: #ffffff;
    cursor: pointer;
}

/* Halftone Dome Stippling Effect Graphic */
.halftone-glow-box {
    position: relative;
    width: 100%;
    height: 180px;
    margin-top: 20px;
    margin-bottom: 30px;
    background: radial-gradient(ellipse at 50% 100%, rgba(255, 255, 255, 0.95) 0%, rgba(255, 180, 200, 0.6) 20%, rgba(220, 38, 76, 0.4) 50%, transparent 80%);
    mask-image: radial-gradient(circle at 50% 100%, black 30%, transparent 80%);
    -webkit-mask-image: radial-gradient(circle at 50% 100%, black 30%, transparent 80%);
    opacity: 0.85;
    border-radius: 50% 50% 0 0;
}

/* Glassmorphism Cards */
.stForm, div[data-testid="stExpander"], div[data-testid="stMetricValue"] {
    background: var(--card-bg) !important;
    border: 1px solid var(--card-border) !important;
    border-radius: 16px !important;
    backdrop-filter: var(--glass-blur) !important;
    box-shadow: 0 12px 36px rgba(0, 0, 0, 0.45) !important;
}

/* Sidebar Custom Styling */
section[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #100407 0%, #20060e 50%, #3a0815 100%) !important;
    border-right: 1px solid rgba(255, 120, 150, 0.12) !important;
}
section[data-testid="stSidebar"] hr {
    border-color: rgba(255, 255, 255, 0.08) !important;
}

/* Primary Mint Glow Buttons */
button[kind="primary"], .stButton > button:hover {
    background: linear-gradient(135deg, var(--mint-accent) 0%, #48e59b 100%) !important;
    color: var(--mint-text) !important;
    font-weight: 600 !important;
    border: none !important;
    border-radius: 9999px !important;
    padding: 10px 24px !important;
    box-shadow: 0 0 25px rgba(110, 231, 183, 0.35) !important;
    transition: all 0.25s ease-in-out !important;
}

.stButton > button {
    background: rgba(255, 255, 255, 0.06) !important;
    color: #ffffff !important;
    border: 1px solid rgba(255, 255, 255, 0.16) !important;
    border-radius: 9999px !important;
    font-weight: 500 !important;
    transition: all 0.2s ease-in-out !important;
}

/* Tabs Styling */
.stTabs [data-baseweb="tab-list"] {
    gap: 8px;
    background: rgba(20, 4, 10, 0.6);
    padding: 6px;
    border-radius: 14px;
    border: 1px solid rgba(255, 120, 150, 0.12);
}
.stTabs [data-baseweb="tab"] {
    height: 42px;
    color: var(--text-muted) !important;
    border-radius: 10px;
    font-weight: 500;
    padding: 0 16px;
}
.stTabs [aria-selected="true"] {
    background: linear-gradient(135deg, rgba(189, 40, 74, 0.4) 0%, rgba(98, 16, 36, 0.6) 100%) !important;
    color: #ffffff !important;
    border: 1px solid rgba(255, 140, 170, 0.3) !important;
}

/* Input Fields & Textareas */
.stTextInput input, .stTextArea textarea, .stSelectbox div[data-baseweb="select"] {
    background-color: rgba(22, 5, 11, 0.8) !important;
    color: #ffffff !important;
    border: 1px solid rgba(255, 120, 150, 0.22) !important;
    border-radius: 10px !important;
}
.stTextInput input:focus, .stTextArea textarea:focus {
    border-color: var(--mint-accent) !important;
    box-shadow: 0 0 12px rgba(110, 231, 183, 0.25) !important;
}

/* Metrics Cards */
div[data-testid="stMetric"] {
    background: rgba(36, 8, 17, 0.55);
    border: 1px solid rgba(255, 120, 150, 0.18);
    border-radius: 14px;
    padding: 16px;
}
div[data-testid="stMetricLabel"] {
    color: var(--text-muted) !important;
}
div[data-testid="stMetricValue"] {
    color: #ffffff !important;
    font-family: 'Newsreader', serif !important;
}

/* Tables & Dataframes */
div[data-testid="stDataFrame"] {
    border: 1px solid rgba(255, 120, 150, 0.18) !important;
    border-radius: 12px !important;
    overflow: hidden !important;
}
</style>
"""

st.markdown(NODAL_CUSTOM_CSS, unsafe_allow_html=True)


# ==========================================
# Helper: First-time Bootstrap Check
# ==========================================
def ensure_initial_setup():
    """Checks if database is empty and creates initial admin if requested."""
    total_users = count_users(DEFAULT_DB_PATH)
    return total_users > 0


# ==========================================
# Sidebar UI Component
# ==========================================
def render_sidebar():
    st.sidebar.markdown(f"## 🛡️ **Aegis AI**")
    st.sidebar.caption("Enterprise AI Identity & Access Control")
    st.sidebar.divider()

    user = get_current_user()
    if user:
        role = user["role"]
        role_color = {
            "admin": "🔴 Admin",
            "researcher": "🔵 Researcher",
            "viewer": "🟢 Viewer"
        }.get(role, role)

        st.sidebar.markdown(f"### 👤 Active Account")
        st.sidebar.write(f"**Username:** `{user['username']}`")
        st.sidebar.write(f"**User ID:** `{user['user_id']}`")
        st.sidebar.write(f"**Assigned Role:** {role_color}")
        st.sidebar.write(f"**Login IP:** `{user.get('login_ip', 'unknown')}`")
        if user.get("ip_alert"):
            st.sidebar.error("⚠️ Signed in from a new IP address")
        
        with st.sidebar.expander("🔑 Granted Permissions"):
            for p in user.get("permissions", []):
                st.write(f"• `{p}`")

        st.sidebar.divider()
        if st.sidebar.button("🚪 Sign Out", use_container_width=True):
            logout_session()
            st.rerun()
    else:
        st.sidebar.info("🔒 Sign in to access your authorized workspace.")
        with st.sidebar.expander("🔑 Demo Quick Access / Credentials"):
            st.markdown(
                """
                - **Admin:** `admin` / `Admin@Secure2026`
                - **Researcher:** `priya` / `User@Secure2026`
                - **Viewer:** `rahul` / `User@Secure2026`
                """
            )

    st.sidebar.divider()
    st.sidebar.markdown("### 🛡️ Security Architecture")
    st.sidebar.markdown(
        """
        - **RBAC Policy:** Zero-trust role-to-permission mapping.
        - **Least Privilege:** Granular function-level guards.
        - **Audit Trails:** Immutable tamper-evident logging.
        """
    )


# ==========================================
# Login & Bootstrap View (Aegis Aesthetic)
# ==========================================
def render_login_view():
    if "top_nav" not in st.session_state:
        st.session_state.top_nav = "Platform"

    # Top Interactive Navigation Bar
    nav_col1, nav_col2, nav_col3, nav_col4, nav_col5, nav_col6 = st.columns([1.8, 1.1, 1.3, 1.2, 1.1, 1.3])

    with nav_col1:
        st.markdown(
            """
            <div style="display: flex; align-items: center; gap: 10px; margin-top: 4px;">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <circle cx="12" cy="6" r="4" fill="#6EE7B7"/>
                    <path d="M4 18C4 14.6863 7.58172 12 12 12C16.4183 12 20 14.6863 20 18" stroke="#ffffff" stroke-width="2.5" stroke-linecap="round"/>
                </svg>
                <span style="font-size: 1.25rem; font-weight: 700; color: #ffffff;">Aegis AI</span>
            </div>
            """,
            unsafe_allow_html=True
        )

    with nav_col2:
        if st.button("⚡ Platform", key="nav_btn_platform", use_container_width=True):
            st.session_state.top_nav = "Platform"
            st.rerun()

    with nav_col3:
        if st.button("🛡️ Policy", key="nav_btn_policy", use_container_width=True):
            st.session_state.top_nav = "Security Policy"
            st.rerun()

    with nav_col4:
        if st.button("📖 Docs", key="nav_btn_docs", use_container_width=True):
            st.session_state.top_nav = "Documentation"
            st.rerun()

    with nav_col5:
        if st.button("📜 Audit", key="nav_btn_audit", use_container_width=True):
            st.session_state.top_nav = "Audit Trails"
            st.rerun()

    with nav_col6:
        if st.button("Get Started →", key="nav_btn_start", type="primary", use_container_width=True):
            st.session_state.top_nav = "Platform"
            st.rerun()

    st.markdown("<div style='margin-bottom: 20px;'></div>", unsafe_allow_html=True)

    # Render Content based on selected interactive navbar button
    if st.session_state.top_nav == "Security Policy":
        st.markdown(
            """
            <div style="text-align: center; margin-bottom: 25px;">
                <div class="pill-badge"><span>🛡️</span><span>Zero-Trust RBAC Policy Matrix</span></div>
                <div class="hero-title" style="font-size: 2.5rem;">Access Control Policy</div>
                <div class="hero-subtitle">Server-enforced role permissions following the Principle of Least Privilege.</div>
            </div>
            """,
            unsafe_allow_html=True
        )
        matrix_data = {
            "Privilege / Resource": [
                "View Platform Benchmarks & Overview",
                "Execute Simulated AI Pipelines",
                "User Management (Create/Edit/Deactivate)",
                "Assign / Change User Roles",
                "Import & Validate User CSV",
                "View Security Audit Logs"
            ],
            "Admin": ["✅ Full Access", "✅ Full Access", "✅ Full Access", "✅ Full Access", "✅ Full Access", "✅ Full Access"],
            "Researcher": ["✅ Authorized", "✅ Authorized", "❌ Denied", "❌ Denied", "❌ Denied", "❌ Denied"],
            "Viewer": ["✅ Read-Only", "❌ Denied", "❌ Denied", "❌ Denied", "❌ Denied", "❌ Denied"]
        }
        st.dataframe(pd.DataFrame(matrix_data), use_container_width=True, hide_index=True)
        st.markdown(
            """
            <div style="background: rgba(30, 6, 14, 0.7); border: 1px solid rgba(255, 120, 150, 0.2); border-radius: 14px; padding: 20px; margin-top: 20px;">
                <h4 style="margin:0 0 10px 0; color: #6ee7b7;">🔒 Fail-Secure & Tamper-Resistant Architecture</h4>
                <p style="color: #e2cad1; font-size: 0.95rem; line-height: 1.6; margin:0;">
                    External permissions from CSV or user input are treated as untrusted metadata. All capabilities are strictly checked against server-side definitions in <code>permissions.py</code> before executing backend actions.
                </p>
            </div>
            """,
            unsafe_allow_html=True
        )
        return

    elif st.session_state.top_nav == "Documentation":
        st.markdown(
            """
            <div style="text-align: center; margin-bottom: 25px;">
                <div class="pill-badge"><span>📖</span><span>System Architecture & Standards</span></div>
                <div class="hero-title" style="font-size: 2.5rem;">System Documentation</div>
                <div class="hero-subtitle">Cryptographic hashing, SQLite persistence, and authorization safeguards.</div>
            </div>
            """,
            unsafe_allow_html=True
        )
        d1, d2 = st.columns(2)
        with d1:
            st.markdown("#### 🔑 Cryptographic Authentication")
            st.markdown(
                """
                - **Algorithm:** Werkzeug `scrypt` & `pbkdf2` password hashing with automatic cryptographic salts.
                - **Timing-Safe Verification:** Constant-time hash comparisons prevent timing side-channel attacks.
                - **Credential Privacy:** Passwords are never logged in plaintext or exposed in error messages.
                """
            )
        with d2:
            st.markdown("#### 🗄️ Database & Security Boundary")
            st.markdown(
                """
                - **Persistent SQLite:** `PRAGMA foreign_keys = ON;` enforces referential integrity.
                - **SQL Injection Defense:** 100% parameterized queries across all database access layers.
                - **Session Security:** Server-side authorization checks on every action.
                """
            )
        return

    elif st.session_state.top_nav == "Audit Trails":
        st.markdown(
            """
            <div style="text-align: center; margin-bottom: 25px;">
                <div class="pill-badge"><span>📜</span><span>Immutable Security Event Logging</span></div>
                <div class="hero-title" style="font-size: 2.5rem;">Audit & Compliance Trails</div>
                <div class="hero-subtitle">Automatic event capture with automatic regex-based credential redaction.</div>
            </div>
            """,
            unsafe_allow_html=True
        )
        logs = get_audit_logs(limit=15, db_path=DEFAULT_DB_PATH)
        if logs:
            st.dataframe(pd.DataFrame(logs)[["id", "username", "event_type", "status", "ip_address", "timestamp"]], use_container_width=True, hide_index=True)
        else:
            st.info("No audit logs recorded yet. Sign in to generate audit events.")
        return

    # DEFAULT: Platform / Hero & Sign In View
    st.markdown(
        """
        <div style="text-align: center; margin-top: 10px; margin-bottom: 25px;">
            <div class="pill-badge">
                <span>🛡️</span>
                <span>For security, research, privacy & audit teams</span>
            </div>
            <div class="hero-title">
                Know who has access.<br/>
                Know what to protect next.
            </div>
            <div class="hero-subtitle">
                Aegis AI brings user identity, role-based authorization, research pipelines, and immutable audit logs
                into one place, so your team can enforce strict least privilege across every AI workflow.
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # Halftone Stippled Glow Visual Feature
    st.markdown(
        """
        <div style="position: relative; width: 100%; text-align: center; margin-bottom: 10px;">
            <div style="
                height: 120px;
                background: radial-gradient(ellipse at 50% 100%, rgba(255, 255, 255, 0.95) 0%, rgba(255, 182, 193, 0.6) 20%, rgba(220, 38, 76, 0.35) 50%, transparent 75%);
                mask-image: radial-gradient(circle at 50% 100%, black 35%, transparent 75%);
                -webkit-mask-image: radial-gradient(circle at 50% 100%, black 35%, transparent 75%);
                opacity: 0.9;
                border-radius: 50% 50% 0 0;
            "></div>
        </div>
        """,
        unsafe_allow_html=True
    )

    db_ready = ensure_initial_setup()
    
    col_l, col1, col2, col_r = st.columns([0.1, 1.1, 1.1, 0.1])

    with col1:
        st.markdown("### 🔐 User Authentication")
        client_ip = get_client_ip()
        st.caption(f"🌐 Your IP address: `{client_ip}` — every sign-in is recorded with its IP. "
                   "Sign-ins from a new IP are flagged to administrators.")
        with st.form("login_form"):
            username = st.text_input("Username", placeholder="e.g., admin, priya, rahul")
            password = st.text_input("Password", type="password", placeholder="Enter password")
            submit = st.form_submit_button("Sign In →", use_container_width=True, type="primary")

            if submit:
                success, user_dict, err = authenticate_user(username, password, ip_address=client_ip, db_path=DEFAULT_DB_PATH)
                if success:
                    login_session(user_dict)
                    st.success(f"Welcome back, {user_dict['username']} ({user_dict['role'].upper()})!")
                    st.rerun()
                else:
                    st.error(err)

    with col2:
        st.markdown("### 🚀 Platform Environment")
        if not db_ready:
            st.warning("⚠️ Database has 0 registered accounts.")
            st.write("Initialize the system with default administrator credentials or import `users.csv`.")
            
            if st.button("⚡ Bootstrap Initial Admin & Import users.csv", use_container_width=True, type="primary"):
                admin_hash = hash_password(DEFAULT_ADMIN_PASSWORD)
                insert_user("ADMIN001", DEFAULT_ADMIN_USERNAME, admin_hash, Role.ADMIN.value, 1, db_path=DEFAULT_DB_PATH)
                
                if os.path.exists("users.csv"):
                    import_users_from_csv("users.csv", default_password=DEFAULT_USER_PASSWORD, db_path=DEFAULT_DB_PATH)
                    st.success("Admin bootstrapped and 30 users imported from `users.csv` successfully!")
                else:
                    st.success("Default administrator created.")
                st.rerun()
        else:
            stats = get_system_metrics(DEFAULT_DB_PATH)
            st.markdown(
                f"""
                <div style="background: rgba(30, 6, 14, 0.7); border: 1px solid rgba(255, 120, 150, 0.2); border-radius: 14px; padding: 18px; margin-bottom: 15px;">
                    <div style="font-size: 1.1rem; font-weight: 600; color: #6ee7b7; margin-bottom: 8px;">
                        ● SQLite Persistent Database Active
                    </div>
                    <div style="color: #e2cad1; font-size: 0.95rem; line-height: 1.6;">
                        • Total Registered Accounts: <b>{stats['total_users']}</b><br/>
                        • Active Users: <b>{stats['active_users']}</b><br/>
                        • Roles: Admin ({stats['role_counts'].get('admin', 0)}), Researcher ({stats['role_counts'].get('researcher', 0)}), Viewer ({stats['role_counts'].get('viewer', 0)})<br/>
                        • Immutable Audit Records: <b>{stats['total_audit_events']}</b>
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )
            
            if os.path.exists("users.csv") and stats['total_users'] < 5:
                if st.button("📥 Import All Users from users.csv", use_container_width=True):
                    res = import_users_from_csv("users.csv", default_password=DEFAULT_USER_PASSWORD, db_path=DEFAULT_DB_PATH)
                    st.success(f"Imported {res['summary']['inserted']} users successfully.")
                    st.rerun()

    st.markdown("---")
    st.markdown("### 📋 Role Privilege Matrix (Principle of Least Privilege)")
    matrix_data = {
        "Privilege / Capability": [
            "View Platform Benchmarks & Overview",
            "Execute Simulated AI Pipelines",
            "Manage Users (Create/Edit/Deactivate)",
            "Assign / Change User Roles",
            "Import & Validate User CSV",
            "View Security Audit Logs"
        ],
        "Admin": ["✅ Allowed", "✅ Allowed", "✅ Allowed", "✅ Allowed", "✅ Allowed", "✅ Allowed"],
        "Researcher": ["✅ Allowed", "✅ Allowed", "❌ Denied", "❌ Denied", "❌ Denied", "❌ Denied"],
        "Viewer": ["✅ Allowed", "❌ Denied", "❌ Denied", "❌ Denied", "❌ Denied", "❌ Denied"]
    }
    st.dataframe(pd.DataFrame(matrix_data), use_container_width=True, hide_index=True)



# ==========================================
# Admin Views
# ==========================================
def render_admin_dashboard(user: dict):
    if not has_permission(user["role"], Permission.MANAGE_USERS.value):
        st.error("🚫 Access Denied: You do not possess administrative permissions.")
        return

    st.markdown(
        """
        <div style="margin-bottom: 20px;">
            <div class="pill-badge" style="margin-bottom: 10px;">
                <span>🔴</span>
                <span>Administrator Security Console • Central Authority</span>
            </div>
            <div style="font-family: 'Newsreader', serif; font-size: 2.4rem; font-weight: 500; color: #ffffff;">
                User Provisioning & System Access
            </div>
            <div style="color: var(--text-secondary); font-size: 0.95rem; margin-top: 4px;">
                Manage user identities, enforce server-side RBAC roles, ingest dataset files, and inspect tamper-proof audit trails.
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    recent_alerts = get_login_history(limit=5, only_new_ip=True, db_path=DEFAULT_DB_PATH)
    if recent_alerts:
        latest = recent_alerts[0]
        st.error(
            f"🚨 **New-IP login alert:** `{latest['username']}` ({latest['role']}) signed in from "
            f"**{latest['ip_address']}** at {latest['timestamp'][:19].replace('T', ' ')} UTC "
            f"(known IPs: {latest['known_ips'] or 'none'}). "
            f"See the **🌐 Login IP Security** tab for all alerts."
        )

    tabs = st.tabs([
        "📊 System Overview",
        "👥 User Management",
        "📥 CSV Importer",
        "📜 Audit Logs",
        "🌐 Login IP Security",
        "🧪 AI Workspace",
        "🛡️ RBAC Security Tester"
    ])

    # --- TAB 1: System Overview ---
    with tabs[0]:
        st.subheader("Platform Metrics")
        metrics = get_system_metrics(DEFAULT_DB_PATH)
        c1, c2, c3, c4, c5 = st.columns(5)
        c1.metric("Total Users", metrics["total_users"])
        c2.metric("Active Accounts", metrics["active_users"])
        c3.metric("Audit Events Logged", metrics["total_audit_events"])
        c4.metric("Failed Login Attempts", metrics["failed_logins"])
        c5.metric("New-IP Login Alerts", metrics["new_ip_alerts"])

        st.markdown("---")
        st.subheader("Role Distribution")
        role_df = pd.DataFrame([
            {"Role": r.upper(), "User Count": metrics["role_counts"].get(r, 0)}
            for r in [Role.ADMIN.value, Role.RESEARCHER.value, Role.VIEWER.value]
        ])
        st.bar_chart(role_df.set_index("Role"))

    # --- TAB 2: User Management ---
    with tabs[1]:
        st.subheader("User Directory & Access Control")
        
        users = get_all_users(DEFAULT_DB_PATH)
        df_users = pd.DataFrame(users)
        
        # Search & Filter
        col_s1, col_s2 = st.columns([2, 1])
        search_query = col_s1.text_input("🔍 Search user by username or ID", "")
        role_filter = col_s2.selectbox("Filter by Role", ["ALL", "admin", "researcher", "viewer"])

        if search_query:
            df_users = df_users[
                df_users["username"].str.contains(search_query, case=False, na=False) |
                df_users["user_id"].str.contains(search_query, case=False, na=False)
            ]
        if role_filter != "ALL":
            df_users = df_users[df_users["role"] == role_filter]

        st.dataframe(df_users, use_container_width=True, hide_index=True)

        st.markdown("---")
        col_u1, col_u2 = st.columns(2)

        # Sub-form: Create User
        with col_u1:
            st.markdown("#### ➕ Create New User")
            with st.form("create_user_form"):
                new_id = st.text_input("User ID", placeholder="e.g. U031")
                new_uname = st.text_input("Username", placeholder="e.g. neha")
                new_pwd = st.text_input("Initial Password", type="password")
                new_role = st.selectbox("Assigned Role", [Role.VIEWER.value, Role.RESEARCHER.value, Role.ADMIN.value])
                new_active = st.checkbox("Active Account", value=True)
                create_btn = st.form_submit_button("Create Account", type="primary")

                if create_btn:
                    ok, msg = admin_create_user(
                        user, new_id, new_uname, new_pwd, new_role, new_active, db_path=DEFAULT_DB_PATH
                    )
                    if ok:
                        st.success(msg)
                        st.rerun()
                    else:
                        st.error(msg)

        # Sub-form: Manage Existing User
        with col_u2:
            st.markdown("#### ⚙️ Modify User Role & Status")
            all_usernames = [u["username"] for u in users]
            target_username = st.selectbox("Select Target User", all_usernames)
            target_user = get_user_by_username(target_username, db_path=DEFAULT_DB_PATH) if target_username else None

            if target_user:
                st.write(f"**Current Role:** `{target_user['role']}` | **Status:** `{'Active' if target_user['is_active'] else 'Deactivated'}`")
                
                with st.form("edit_user_form"):
                    updated_role = st.selectbox(
                        "Change Role",
                        [Role.ADMIN.value, Role.RESEARCHER.value, Role.VIEWER.value],
                        index=[Role.ADMIN.value, Role.RESEARCHER.value, Role.VIEWER.value].index(target_user["role"])
                    )
                    updated_active = st.checkbox("Account is Active", value=bool(target_user["is_active"]))
                    new_reset_pwd = st.text_input("Reset Password (optional)", type="password", placeholder="Leave empty to keep current")
                    save_btn = st.form_submit_button("Apply Changes", type="primary")

                    if save_btn:
                        # 1. Role Update
                        if updated_role != target_user["role"]:
                            admin_change_role(user, target_user["user_id"], updated_role, db_path=DEFAULT_DB_PATH)
                        # 2. Status Update
                        if updated_active != bool(target_user["is_active"]):
                            admin_toggle_status(user, target_user["user_id"], updated_active, db_path=DEFAULT_DB_PATH)
                        # 3. Password Reset
                        if new_reset_pwd and len(new_reset_pwd) >= 6:
                            admin_reset_password(user, target_user["user_id"], new_reset_pwd, db_path=DEFAULT_DB_PATH)
                        
                        st.success(f"User '{target_user['username']}' updated successfully.")
                        st.rerun()

    # --- TAB 3: CSV Importer ---
    with tabs[2]:
        st.subheader("Safe CSV Ingestion & Policy Enforcement")
        st.markdown(
            """
            This importer reads external user datasets, validates formatting and roles,
            enforces the centralized server-side RBAC policy, and loads accounts without
            overwriting existing password credentials.
            """
        )

        col_c1, col_c2 = st.columns([1, 1])
        with col_c1:
            st.markdown("#### Import from Local Workspace `users.csv`")
            default_csv_pass = st.text_input("Default Password for New Accounts", value=DEFAULT_USER_PASSWORD, type="password")
            update_roles_flag = st.checkbox("Update roles for existing users if CSV differs", value=False)
            
            if st.button("🚀 Process `users.csv`", use_container_width=True, type="primary"):
                if os.path.exists("users.csv"):
                    with st.spinner("Validating and importing records..."):
                        report = import_users_from_csv(
                            "users.csv",
                            default_password=default_csv_pass,
                            update_roles_if_exists=update_roles_flag,
                            db_path=DEFAULT_DB_PATH,
                            acting_user=user
                        )
                    st.success("CSV Import Process Completed.")
                    st.session_state.last_import_report = report
                else:
                    st.error("File `users.csv` was not found in the workspace root.")

        with col_c2:
            st.markdown("#### Upload Custom CSV File")
            uploaded_file = st.file_uploader("Choose a CSV file", type=["csv"])
            if uploaded_file is not None:
                temp_path = "temp_uploaded_users.csv"
                with open(temp_path, "wb") as f:
                    f.write(uploaded_file.getbuffer())
                
                if st.button("🚀 Import Uploaded File", use_container_width=True, type="primary"):
                    with st.spinner("Processing uploaded CSV..."):
                        report = import_users_from_csv(
                            temp_path,
                            default_password=default_csv_pass,
                            update_roles_if_exists=update_roles_flag,
                            db_path=DEFAULT_DB_PATH,
                            acting_user=user
                        )
                    st.session_state.last_import_report = report
                    if os.path.exists(temp_path):
                        os.remove(temp_path)
                    st.success("Uploaded file imported successfully.")

        # Show Import Report if available
        if "last_import_report" in st.session_state:
            rep = st.session_state.last_import_report
            st.markdown("---")
            st.subheader("📋 Import Summary Report")
            
            rc1, rc2, rc3, rc4 = st.columns(4)
            rc1.metric("Processed Rows", rep["summary"]["total"])
            rc2.metric("Inserted (New)", rep["summary"]["inserted"])
            rc3.metric("Skipped (Existing)", rep["summary"]["skipped"])
            rc4.metric("Malformed / Errors", rep["summary"]["errors"])

            if rep["errors"]:
                st.warning("⚠️ Rejected Rows:")
                st.dataframe(pd.DataFrame(rep["errors"]), use_container_width=True)

            if rep["inserted"]:
                with st.expander(f"✅ View Inserted Users ({len(rep['inserted'])})"):
                    st.dataframe(pd.DataFrame(rep["inserted"]), use_container_width=True)

            if rep["skipped"]:
                with st.expander(f"ℹ️ View Skipped Existing Users ({len(rep['skipped'])})"):
                    st.dataframe(pd.DataFrame(rep["skipped"]), use_container_width=True)

    # --- TAB 4: Audit Logs ---
    with tabs[3]:
        st.subheader("📜 Security Audit Logs")
        st.caption("Immutable record of system events, authentication attempts, and authorization decisions.")

        col_f1, col_f2, col_f3 = st.columns([1, 1, 1])
        event_filter = col_f1.selectbox(
            "Event Filter",
            ["ALL"] + [e.value for e in AuditEvent]
        )
        user_filter_txt = col_f2.text_input("User Search Filter", "")
        log_limit = col_f3.slider("Max Logs to Show", 10, 500, 100)

        logs = get_audit_logs(
            limit=log_limit,
            event_type=event_filter,
            user_filter=user_filter_txt,
            db_path=DEFAULT_DB_PATH
        )

        if logs:
            df_logs = pd.DataFrame(logs)
            st.dataframe(df_logs, use_container_width=True, hide_index=True)
            
            # Export CSV
            csv_data = df_logs.to_csv(index=False).encode('utf-8')
            st.download_button(
                "📥 Export Audit Logs as CSV",
                data=csv_data,
                file_name=f"audit_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
        else:
            st.info("No audit logs matched your query.")

    # --- TAB 5: Login IP Security ---
    with tabs[4]:
        render_login_ip_security()

    # --- TAB 6: AI Workspace ---
    with tabs[5]:
        render_ai_workspace(user)

    # --- TAB 7: Security Sandbox ---
    with tabs[6]:
        render_security_tester(user)


def render_login_ip_security():
    st.subheader("🌐 Login IP Monitoring & New-IP Alerts")
    st.caption(
        "Every successful sign-in is stored in the SQLite `login_history` table with its IP address. "
        "A user's first IP is registered as known; a later sign-in from a different IP is allowed "
        "but flagged as a NEW_IP_LOGIN alert."
    )

    alerts = get_login_history(limit=200, only_new_ip=True, db_path=DEFAULT_DB_PATH)
    st.markdown(f"#### 🚨 Flagged Sign-ins ({len(alerts)})")
    if alerts:
        df_alerts = pd.DataFrame(alerts)[["timestamp", "username", "role", "ip_address", "known_ips"]]
        df_alerts.columns = ["Time (UTC)", "Username", "Role", "New IP", "Previously Known IPs"]
        st.dataframe(df_alerts, use_container_width=True, hide_index=True)
    else:
        st.success("No sign-ins from unrecognized IP addresses so far.")

    st.markdown("#### 👤 Known IPs per User")
    summary = get_user_ip_summary(db_path=DEFAULT_DB_PATH)
    if summary:
        df_sum = pd.DataFrame(summary)[["username", "role", "total_logins", "distinct_ips", "new_ip_alerts", "ip_addresses", "last_login"]]
        st.dataframe(df_sum, use_container_width=True, hide_index=True)
    else:
        st.info("No sign-ins recorded yet.")

    st.markdown("#### 📒 Full Login History")
    history = get_login_history(limit=500, db_path=DEFAULT_DB_PATH)
    if history:
        df_hist = pd.DataFrame(history)
        df_hist["flag"] = df_hist["is_new_ip"].map({1: "🚨 NEW IP", 0: "✅ known"})
        st.dataframe(df_hist[["id", "timestamp", "username", "role", "ip_address", "flag"]], use_container_width=True, hide_index=True)
        st.download_button(
            "📥 Export Login History as CSV",
            data=df_hist.to_csv(index=False).encode("utf-8"),
            file_name=f"login_history_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )

    log_path = get_security_log_path(DEFAULT_DB_PATH)
    st.markdown("#### 📄 Security Log File")
    if log_path.exists():
        lines = log_path.read_text(encoding="utf-8").splitlines()
        st.code("\n".join(lines[-30:]) or "(empty)", language="text")
        st.download_button(
            f"📥 Download {log_path.name}",
            data="\n".join(lines).encode("utf-8"),
            file_name=log_path.name,
            mime="text/plain"
        )
    else:
        st.info(f"`{log_path.name}` will be created on the first security event.")


# ==========================================
# Researcher Views
# ==========================================
def render_researcher_dashboard(user: dict):
    if not has_permission(user["role"], Permission.RUN_AI.value):
        st.error("🚫 Access Denied: You do not possess research execution permissions.")
        return

    st.markdown(
        f"""
        <div style="margin-bottom: 20px;">
            <div class="pill-badge" style="margin-bottom: 10px;">
                <span>🔵</span>
                <span>Researcher Workspace • Least Privilege Scope</span>
            </div>
            <div style="font-family: 'Newsreader', serif; font-size: 2.4rem; font-weight: 500; color: #ffffff;">
                AI Pipeline & Privacy Analysis
            </div>
            <div style="color: var(--text-secondary); font-size: 0.95rem; margin-top: 4px;">
                Authenticated Researcher: <b style="color:#6ee7b7;">{user['username']}</b>. Execute NLP pipelines, inspect benchmark metrics, and verify data privacy guards.
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    tabs = st.tabs([
        "🧪 Deterministic AI Tool",
        "📊 Research Experiments",
        "🛡️ RBAC Security Tester"
    ])

    with tabs[0]:
        render_ai_workspace(user)

    with tabs[1]:
        st.subheader("Saved Experiment Benchmarks")
        experiments = get_ai_experiments(limit=50, db_path=DEFAULT_DB_PATH)
        if experiments:
            st.dataframe(pd.DataFrame(experiments)[["id", "username", "analysis_type", "input_snippet", "summary_output", "created_at"]], use_container_width=True, hide_index=True)
        else:
            st.info("No experiment runs recorded yet. Use the Deterministic AI Tool to run analyses.")

    with tabs[2]:
        render_security_tester(user)


# ==========================================
# Viewer Views
# ==========================================
def render_viewer_dashboard(user: dict):
    if not has_permission(user["role"], Permission.VIEW_RESULTS.value):
        st.error("🚫 Access Denied.")
        return

    st.markdown(
        f"""
        <div style="margin-bottom: 20px;">
            <div class="pill-badge" style="margin-bottom: 10px;">
                <span>🟢</span>
                <span>Viewer Dashboard • Read-Only Scope</span>
            </div>
            <div style="font-family: 'Newsreader', serif; font-size: 2.4rem; font-weight: 500; color: #ffffff;">
                Published AI Benchmarks
            </div>
            <div style="color: var(--text-secondary); font-size: 0.95rem; margin-top: 4px;">
                Authenticated as <b style="color:#6ee7b7;">{user['username']}</b>. Access permitted to non-sensitive summaries and shared research reports.
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    tabs = st.tabs([
        "📊 Published Benchmarks",
        "ℹ️ Platform Statistics",
        "🛡️ RBAC Security Tester"
    ])

    with tabs[0]:
        st.subheader("Published AI Model Benchmarks (Read-Only)")
        experiments = get_ai_experiments(limit=20, db_path=DEFAULT_DB_PATH)
        if experiments:
            for exp in experiments:
                with st.expander(f"📌 Experiment #{exp['id']} by `{exp['username']}` ({exp['analysis_type']}) - {exp['created_at']}"):
                    st.write(f"**Input Snippet:** {exp['input_snippet']}")
                    st.write(f"**Generated Summary:** {exp['summary_output']}")
                    st.json(exp.get("metrics", {}))
        else:
            st.info("No published experiments currently available.")

    with tabs[1]:
        st.subheader("Public Platform Metrics")
        metrics = get_system_metrics(DEFAULT_DB_PATH)
        c1, c2 = st.columns(2)
        c1.metric("Registered Accounts", metrics["total_users"])
        c2.metric("AI Experiments Executed", metrics["total_ai_runs"])

    with tabs[2]:
        render_security_tester(user)


# ==========================================
# Common AI Workspace Component
# ==========================================
def render_ai_workspace(user: dict):
    st.subheader("🧪 AI Inference & Text Analytics Pipeline")
    st.info(
        "⚡ **Protected AI Execution Engine:** Real-time deterministic NLP analytics, entity extraction, and data privacy scanner."
    )

    preset = st.selectbox(
        "Select a Sample Text Preset or Type Your Own:",
        [
            "Custom Input",
            "Medical Record Abstract (Privacy-Sensitive)",
            "AI Security & Privacy Research Note",
            "Customer Support Interaction Transcript"
        ]
    )

    sample_texts = {
        "Medical Record Abstract (Privacy-Sensitive)": (
            "Patient John Doe (john.doe@hospital.org, phone 555-019-2831, SSN 000-12-3456) was admitted for clinical evaluation. "
            "The diagnostic machine learning pipeline exhibited high accuracy and optimal performance during classification. "
            "However, strict data privacy controls and role-based access must prevent data leak risks in healthcare records."
        ),
        "AI Security & Privacy Research Note": (
            "Role-Based Access Control provides robust security architecture for machine learning platforms. "
            "By enforcing least privilege, researchers can run intelligent inference while preventing unauthorized administrative access. "
            "Secure password hashing with Werkzeug ensures credential integrity against database breach vulnerabilities."
        ),
        "Customer Support Interaction Transcript": (
            "Customer Jane Smith contacted support regarding login failure. The support engineer verified the account status. "
            "After resetting the credentials, the customer achieved fast and seamless login. Overall satisfaction was positive."
        )
    }

    initial_val = sample_texts.get(preset, "")
    user_text = st.text_area("Input Text for Analysis", value=initial_val, height=140)

    col1, col2 = st.columns(2)
    analysis_type = col1.selectbox("Analysis Pipeline Mode", ["Comprehensive NLP", "Privacy & PII Audit", "Keyword Density"])
    max_kw = col2.slider("Max Keywords", 3, 10, 5)

    if st.button("⚡ Execute AI Analysis", type="primary"):
        if not user_text.strip():
            st.warning("Please enter some text to analyze.")
            return

        try:
            # Enforces server-side authorization directly in service layer
            with st.spinner("Processing text via deterministic NLP pipeline..."):
                res = execute_ai_research_task(
                    user=user,
                    input_text=user_text,
                    analysis_type=analysis_type,
                    max_keywords=max_kw,
                    db_path=DEFAULT_DB_PATH
                )

            st.success("✅ Execution Successful (Server-Side Permission Verified)")
            
            # Results Display
            r1, r2, r3, r4 = st.columns(4)
            r1.metric("Word Count", res["word_count"])
            r2.metric("Sentiment", f"{res['sentiment']} ({res['sentiment_score']})")
            r3.metric("Readability Index", f"{res['readability_index']} / 100")
            r4.metric("PII Items Detected", len(res["pii_detected"]))

            st.markdown("#### 📝 Extractive Summary")
            st.write(res["summary"])

            col_k1, col_k2 = st.columns(2)
            with col_k1:
                st.markdown("#### 🔑 Extracted Keywords")
                st.dataframe(pd.DataFrame(res["keywords"]), use_container_width=True, hide_index=True)

            with col_k2:
                st.markdown("#### 🛡️ Simulated Privacy / PII Findings")
                if res["pii_detected"]:
                    st.dataframe(pd.DataFrame(res["pii_detected"]), use_container_width=True, hide_index=True)
                else:
                    st.info("No simulated PII tokens detected.")

        except PermissionError as pe:
            st.error(f"🚫 {str(pe)}")


# ==========================================
# Common Security Tester Component
# ==========================================
def render_security_tester(user: dict):
    st.subheader("🛡️ Interactive RBAC Security Sandbox & Privilege Escalation Tester")
    st.markdown(
        """
        Use this interactive tester to prove that permissions are enforced strictly on the server-side.
        Attempting unauthorized operations will be rejected and immutably recorded in the audit logs.
        """
    )

    st.write(f"**Active User:** `{user['username']}` | **Current Role:** `{user['role'].upper()}`")

    col1, col2, col3 = st.columns(3)

    with col1:
        st.markdown("##### 1. Attempt Administrative Action")
        st.caption("Requires `manage_users` permission")
        if st.button("Trigger Admin User Creation", key="test_admin_action"):
            ok, msg = admin_create_user(
                acting_user=user,
                user_id="HACK001",
                username="unauthorized_user",
                password="Password123",
                role="admin",
                db_path=DEFAULT_DB_PATH
            )
            if ok:
                st.success(f"Operation Allowed: {msg}")
            else:
                st.error(f"🛑 Blocked Server-Side: {msg}")

    with col2:
        st.markdown("##### 2. Attempt AI Pipeline Execution")
        st.caption("Requires `run_ai` permission")
        if st.button("Trigger AI Analysis Run", key="test_ai_action"):
            try:
                execute_ai_research_task(
                    user=user,
                    input_text="Unauthorized test payload",
                    analysis_type="Security Probe",
                    db_path=DEFAULT_DB_PATH
                )
                st.success("Operation Allowed: AI Pipeline executed successfully.")
            except PermissionError as pe:
                st.error(f"🛑 Blocked Server-Side: {str(pe)}")

    with col3:
        st.markdown("##### 3. Attempt Audit Log Inspection")
        st.caption("Requires `view_audit_logs` permission")
        if st.button("Query System Audit Table", key="test_audit_action"):
            if has_permission(user["role"], Permission.VIEW_AUDIT_LOGS.value):
                st.success("Operation Allowed: Audit logs viewable.")
            else:
                log_event(
                    AuditEvent.ACCESS_DENIED,
                    f"User '{user['username']}' attempted unauthorized audit log access",
                    user_id=user["user_id"],
                    username=user["username"],
                    status="DENIED",
                    db_path=DEFAULT_DB_PATH
                )
                st.error("🛑 Blocked Server-Side: Access Denied. Insufficient privileges to read audit logs.")


# ==========================================
# Main Router
# ==========================================
def main():
    render_sidebar()
    user = get_current_user()

    if not user:
        render_login_view()
    else:
        alert = user.get("ip_alert")
        if alert:
            st.warning(
                f"⚠️ **Sign-in from a new IP address detected.** This session comes from "
                f"`{alert['new_ip']}`, which differs from your known IP(s): `{', '.join(alert['known_ips'])}`. "
                f"The sign-in was allowed, but it has been recorded and reported to administrators."
            )
        role = user.get("role", "").lower()
        if role == Role.ADMIN.value:
            render_admin_dashboard(user)
        elif role == Role.RESEARCHER.value:
            render_researcher_dashboard(user)
        elif role == Role.VIEWER.value:
            render_viewer_dashboard(user)
        else:
            st.error(f"Unknown or unauthorized role: '{role}'")
            if st.button("Log Out"):
                logout_session()
                st.rerun()


if __name__ == "__main__":
    main()
