# Role-Based Access Control (RBAC) System for an AI Platform

A complete, production-grade college mini-project for **Data Security and Privacy**, demonstrating secure user authentication, fine-grained server-side Role-Based Access Control (RBAC), principle of least privilege, tamper-resistant CSV data ingestion, and immutable audit logging.

---

## 1. Project Overview & Security Concepts

### What is Role-Based Access Control (RBAC)?
Role-Based Access Control (RBAC) is an access control mechanism where access permissions are assigned to specific **roles** rather than directly to individual users. Users are assigned roles, thereby inheriting only the permissions strictly associated with those roles.

### Principle of Least Privilege (PoLP)
Every module and user role is granted the minimum levels of access—and only those authorizations—necessary to perform its specified tasks:
- **Admin**: Full control over user provisioning, role assignments, system status, CSV ingestion, and security audit log inspection.
- **Researcher**: Restricted to executing simulated AI NLP/privacy pipelines, tuning parameters, and analyzing experiment benchmarks. Cannot manage users, alter permissions, or inspect audit logs.
- **Viewer**: Read-only access to published AI model benchmarks and public statistics. Strictly forbidden from executing AI tasks or accessing administrative endpoints.

### Authentication vs. Authorization
- **Authentication (AuthN):** "Who are you?" Verified via usernames and cryptographic password hashes (`werkzeug.security` with scrypt/pbkdf2).
- **Authorization (AuthZ):** "What are you permitted to do?" Enforced strictly on the server-side via `permissions.py` before executing any protected operation or rendering sensitive views.

### Audit Logging & Non-Repudiation
All critical security events (login success/failure, user creation, role modification, account deactivation, and unauthorized privilege escalation attempts) are immutably logged to the SQLite database with timestamps, actor IDs, event types, and sanitized descriptions.

---

## 2. Project Directory Structure

```text
AI_Devansh/
│
├── app.py                  # Main Streamlit web application & multi-role UI
├── database.py             # SQLite database layer with foreign keys & parameterized queries
├── permissions.py          # Centralized RBAC policy & role-to-permission mapping
├── auth.py                 # Werkzeug password hashing, auth verification, and admin operations
├── audit.py                # Security audit logging with automatic parameter redaction
├── import_users.py         # CSV inspection, validation, idempotent loading & report generation
├── ai_service.py           # Protected deterministic AI text analytics & PII scan pipeline
├── config.py               # Application configuration & environment loader
│
├── users.csv               # Provided dataset with 30 user records
├── requirements.txt        # Python dependency manifest
├── .env.example            # Configuration template with security placeholders
├── README.md               # Project documentation, setup guide, and theory
│
└── tests/                  # Automated pytest test suites
    ├── conftest.py         # Isolated temporary database fixtures
    ├── test_auth.py        # Authentication & user management tests
    ├── test_permissions.py # RBAC policy & least privilege tests
    ├── test_import.py      # CSV validation, idempotency & error handling tests
    ├── test_audit.py       # Security audit logging & redaction tests
    └── test_ai_service.py  # Simulated AI execution & authorization barrier tests
```

---

## 3. Dataset Analysis (`users.csv`)

The provided dataset contains 30 fictional records across three distinct user roles:
- **Actual Columns:** `user_id,username,role,permissions`
- **Roles Present:**
  - `admin` (4 users: `arun`, `kavya`, `karan`, `sana`)
  - `researcher` (13 users: `priya`, `sneha`, `rohan`, `vikram`, `dev`, `ananya`, `riya`, `tanvi`, `diya`, `yash`, `om`, `arjun`, `kabir`)
  - `viewer` (13 users: `rahul`, `amit`, `meera`, `isha`, `nisha`, `manav`, `aditya`, `ishan`, `neel`, `pari`, `zoya`, `mira`, `tara`)
- **Untrusted Input Handling:** The CSV contains an unhashed list of permissions (`Manage users; Run AI; View results`). In our architecture, the `permissions` column is treated as untrusted metadata. The application strictly binds access rights to the server-side RBAC policy in [permissions.py](file:///c:/Users/HP/Desktop/AI_Devansh/permissions.py).
- **Password Policy:** As external user directory files do not contain passwords, the importer initializes new accounts with a secure hash of `DEFAULT_USER_PASSWORD` (`User@Secure2026`), allowing immediate evaluation and admin-controlled password resets.

---

## 4. Installation & Setup Instructions

### Prerequisites
- Python 3.10+ (tested on Python 3.14)
- `pip` package manager

### Step 1: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 2: Configure Environment (Optional)
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```
Default parameters configured:
- `DEFAULT_ADMIN_USERNAME`: `admin`
- `DEFAULT_ADMIN_PASSWORD`: `Admin@Secure2026`
- `DEFAULT_USER_PASSWORD`: `User@Secure2026`
- `DB_PATH`: `rbac_platform.db`

### Step 3: Import `users.csv` into SQLite Database
You can import records via the command-line importer:
```bash
python import_users.py --csv users.csv
```
*(Or use the 1-click bootstrap button on the Streamlit web application).*

---

## 5. Running Automated Tests

Run the automated test suite using `pytest`:
```bash
python -m pytest -v
```

### Test Verification Results
All 24 automated unit and integration tests execute successfully in isolated SQLite environments:
```text
tests/test_ai_service.py::test_deterministic_text_analysis PASSED        [  4%]
tests/test_ai_service.py::test_researcher_ai_execution_authorized PASSED [  8%]
tests/test_ai_service.py::test_admin_ai_execution_authorized PASSED      [ 12%]
tests/test_ai_service.py::test_viewer_ai_execution_denied PASSED         [ 16%]
tests/test_audit.py::test_audit_log_creation PASSED                      [ 20%]
tests/test_audit.py::test_failed_login_creates_audit_log PASSED          [ 25%]
tests/test_audit.py::test_password_redaction_in_audit_logs PASSED        [ 29%]
tests/test_auth.py::test_password_hashing_and_verification PASSED        [ 33%]
tests/test_auth.py::test_successful_login PASSED                         [ 37%]
tests/test_auth.py::test_failed_login_wrong_password PASSED              [ 41%]
tests/test_auth.py::test_failed_login_nonexistent_user PASSED            [ 45%]
tests/test_auth.py::test_inactive_account_login_denial PASSED            [ 50%]
tests/test_auth.py::test_admin_create_user_authorized PASSED             [ 54%]
tests/test_auth.py::test_admin_create_user_unauthorized PASSED           [ 58%]
tests/test_auth.py::test_admin_role_change PASSED                        [ 62%]
tests/test_auth.py::test_admin_prevent_self_deactivation PASSED          [ 66%]
tests/test_import.py::test_import_actual_users_csv PASSED                [ 70%]
tests/test_import.py::test_import_idempotency_preserves_passwords PASSED [ 75%]
tests/test_import.py::test_import_malformed_records PASSED               [ 79%]
tests/test_permissions.py::test_admin_permissions PASSED                 [ 83%]
tests/test_permissions.py::test_researcher_least_privilege PASSED        [ 87%]
tests/test_permissions.py::test_viewer_least_privilege PASSED            [ 91%]
tests/test_permissions.py::test_invalid_role_fail_secure PASSED          [ 95%]
tests/test_permissions.py::test_page_routing_access_matrix PASSED        [100%]

============================= 24 passed in 11.60s =============================
```

---

## 6. Launching the Streamlit Web Application

Start the application dev server:
```bash
streamlit run app.py
```

The application will be accessible at:
- **Local URL:** `http://localhost:8501`

---

## 7. Role Demonstration & Walkthrough Guide

### Scenario 1: Administrator Demonstration (`admin` or `arun`)
1. **Login:** Use username `admin` (password `Admin@Secure2026`) or `arun` (password `User@Secure2026`).
2. **Dashboard Overview:** Review system-wide metrics (total accounts, active/inactive split, failed login attempts count).
3. **User Management:**
   - Search the 30 imported users by username or role.
   - Provision a new account (`U031`, `neha`, `researcher`).
   - Modify an existing user's role (e.g., promote `rahul` to `researcher`).
   - Deactivate an account and verify login rejection.
4. **Audit Logs:** Filter audit logs by `LOGIN_FAILED`, `USER_CREATED`, or `PRIVILEGE_ESCALATION_BLOCKED`. Export logs as CSV.
5. **CSV Ingestion:** Re-run or upload a new CSV file to observe the live validation summary report.

### Scenario 2: Researcher Demonstration (`priya` or `dev`)
1. **Login:** Use username `priya` (password `User@Secure2026`).
2. **AI Workspace:** Select the *"Medical Record Abstract"* preset or input research text.
3. **Execution:** Run the deterministic NLP & Privacy analysis pipeline to obtain keywords, extractive summary, sentiment score, readability index, and detected simulated PII tokens.
4. **RBAC Sandbox:** Switch to the **RBAC Security Tester** tab and attempt to create an administrative user. Notice the immediate `Access Denied` feedback and security audit recording.

### Scenario 3: Viewer Demonstration (`rahul` or `amit`)
1. **Login:** Use username `rahul` (password `User@Secure2026`).
2. **Read-Only Dashboard:** View aggregate public metrics and published research experiment summaries.
3. **Access Enforcement:** Attempt to execute an AI research pipeline in the Security Sandbox. Observe that the server-side guard blocks the request and raises a permission violation.

---

## 8. Security Analysis & Prototype Limitations

1. **Server-Side Enforcement:** Access checks are performed on every backend function (`has_permission`), ensuring security is independent of UI controls or hidden HTML elements.
2. **SQL Injection Defense:** All SQLite queries utilize parameterized bindings (`?`), mitigating injection risks.
3. **Timing & Enumeration Protection:** Generic error messages (`"Invalid username or password"`) prevent username harvesting.
4. **Prototype Boundaries:** In a production multi-tenant deployment, Streamlit session states should be paired with signed JWTs or Redis-backed session stores with short expiry times and HTTPS transport security.
