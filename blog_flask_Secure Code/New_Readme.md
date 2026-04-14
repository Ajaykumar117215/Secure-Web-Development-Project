# The Travel Blog — Secure Flask Application

**Original Repository:** https://github.com/bgtti/blog_flask  
**Option:** A (existing project with notable security vulnerabilities)  
**Module:** Secure Web Development — NCI MSCCYB1  
**Assessment Date:** April 2026

---

## Project Title and Overview

This project takes an existing open-source Flask blog application (bgtti/blog_flask) and systematically hardens it against 14 identified security vulnerabilities spanning OWASP Top 10 categories. The original codebase provides a fully functional multi-user travel blog. All security improvements were implemented in the student's own code — no AI-generated code was used.

The primary security focus areas are:
- Broken Access Control (OWASP A01)
- Injection / Stored XSS (OWASP A03)
- Security Misconfiguration (OWASP A05)
- Identification and Authentication Failures (OWASP A07)

---

## Features and Security Objectives

### Application Features
- User registration, login, and profile management
- Blog post creation, editing, approval, and deletion
- Commenting and reply system with likes and bookmarks
- Admin dashboard for user and content management
- Contact form with email notification
- Four content themes with dedicated post views
- Four user roles: `super_admin`, `admin`, `author`, `user`

### Security Improvements Made

| ID | Vulnerability | Fix Applied |
|----|--------------|-------------|
| V-01 | Hardcoded `SECRET_KEY` | Loaded from `.env` via `os.getenv()` — startup fails if absent |
| V-02 | IDOR on account update/delete/picture routes | `abort(403)` if `id != current_user.id` |
| V-03 | Missing role check on admin routes | `abort(403)` if `current_user.type` not in `(admin, super_admin)` |
| V-04 | No brute-force protection on login | `@limiter.limit("5 per minute")` + unified error message |
| V-05 | No password complexity enforcement | Min 8 chars, 1 uppercase, 1 digit enforced server-side at signup |
| V-06 | Stored XSS via CKEditor post bodies | `bleach.clean()` allowlist sanitisation before DB storage |
| V-07 | Missing CSRF on JSON API endpoints | `validate_csrf(X-CSRFToken header)` + `csrf_token()` meta tag in HTML |
| V-08 | Unauthenticated comment/reply deletion | `@login_required` + ownership check before deletion |
| V-09 | No email format validation at signup | `Email()` validator in WTForms + regex check in route |
| V-10 | No session timeout | `PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)` + `SESSION_COOKIE_HTTPONLY/SAMESITE` |
| V-11 | Missing HTTP security headers | `after_request` hook sets CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy |
| V-12 | Client-side file size bypass | Server-side `seek(0,2)/tell()/seek(0)` measurement replaces client form field |
| V-13 | No rate limiting on contact form | `@limiter.limit("5 per 10 minutes", methods=["POST"])` |
| V-14 | Verbose exception disclosure (added) | Generic error rendered; exception logged server-side only (`logger.error`) |

---

## Project Structure

```
blog_flask/
├── app/
│   ├── __init__.py              # App factory — initialises extensions, security headers (V-11)
│   ├── config.py                # Configuration — SECRET_KEY from env (V-01), session settings (V-10)
│   ├── extensions.py            # SQLAlchemy, CKEditor, LoginManager, CSRFProtect, Limiter
│   ├── account/
│   │   ├── forms.py             # WTForms — Email() validator added (V-09)
│   │   └── routes.py            # Login rate-limit (V-04), IDOR checks (V-02), password rules (V-05)
│   ├── dashboard/
│   │   └── routes.py            # Role guards (V-03), bleach XSS sanitisation (V-06), server-side file size (V-12)
│   ├── website/
│   │   └── routes.py            # CSRF on JSON API (V-07), auth+ownership on delete (V-08),
│   │                            # rate-limited contact (V-13), generic error message (V-14)
│   ├── models/                  # SQLAlchemy ORM models
│   ├── static/
│   │   └── JS/app.js            # getCsrfToken() helper + X-CSRFToken in all fetch headers (V-07)
│   └── templates/
│       └── base.html            # <meta name="csrf-token"> CSRF token injection (V-07)
├── create_db.py                 # Seeds database with dummy data on first run
├── run.py                       # Application entry point
├── requirements_new.txt         # Verified dependency list (Python 3.14+ compatible)
├── .env                         # SECRET_KEY + email credentials (NOT committed to repo)
├── Vulnerabilities.md           # Detailed vulnerability analysis with OWASP/CWE references
└── New_Readme.md                # This file
```

---

## Setup and Installation Instructions

### Prerequisites
- Python 3.10+ (`python --version`)
- pip (`pip --version`)
- Git

### Step 1 — Clone the repository

```bash
git clone <your-repo-url>
cd blog_flask
```

### Step 2 — Create and activate a virtual environment

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate
```

### Step 3 — Install dependencies

```bash
pip install -r requirements_new.txt
```

> **Note:** `requirements_new.txt` contains verified package versions compatible with Python 3.10+. The original `requirements.txt` pins older versions that do not install cleanly on newer Python interpreters.

### Step 4 — Create the `.env` file

Create a file named `.env` in the project root (same directory as `run.py`):

```
SECRET_KEY=<generate with: python -c "import secrets; print(secrets.token_hex(32))">
EMAIL_ADDRESS=your_gmail@gmail.com
EMAIL_PASSWORD=your_gmail_app_password
```

- `SECRET_KEY` is **required** — the application will not start without it (V-01 fix).
- `EMAIL_ADDRESS` and `EMAIL_PASSWORD` are optional; the contact form will still render without them but email delivery will fail.

> **Security note:** Never commit `.env` to version control. Add it to `.gitignore`.

### Step 5 — Run the application

```bash
python run.py
```

On first run the SQLite database is created at `instance/admin.db` and populated with dummy data automatically.

### Step 6 — Open in browser

```
http://127.0.0.1:5000
```

### Reset the Database

```bash
# Windows
rmdir /s /q instance

# macOS / Linux
rm -rf instance/

python run.py
```

---

## Usage Guidelines

### Pre-loaded Test Accounts

| Role | Email | Password |
|------|-------|----------|
| Super Admin | `super@admin` | `admin123` |
| Admin | `r@r` | `user123` |
| Author | `e@e` | `user123` |
| Regular User | `j@m` | `user123` |

> **Note:** Pre-loaded passwords were set before the password complexity rule (V-05) was applied. New accounts created through the signup form must meet the complexity requirements (min 8 chars, 1 uppercase, 1 digit).

### Key Navigation Paths

| Action | URL |
|--------|-----|
| Home | `/` |
| All Posts | `/all/0` |
| Login | `/login` |
| Sign Up | `/signup` |
| User Dashboard | `/dashboard` |
| Admin Users Table | `/dashboard/manage_users` |
| Contact | `/contact/` |

### Role Capabilities

| Feature | user | author | admin | super_admin |
|---------|------|--------|-------|-------------|
| Read posts | Yes | Yes | Yes | Yes |
| Comment / Like / Bookmark | Yes | Yes | Yes | Yes |
| Submit new posts | No | Yes | Yes | Yes |
| Approve / reject posts | No | No | Yes | Yes |
| Manage users | No | No | Yes | Yes |
| Delete super_admin account | No | No | No | No |

---

## Security Improvements

### V-01 — Hardcoded Secret Key (Critical)
**File:** [app/config.py](app/config.py)  
**OWASP:** A05 — Security Misconfiguration | **CWE:** CWE-798

The original code set `SECRET_KEY = "myFlaskApp4Fun"` in plain source. Flask uses this key to sign session cookies — anyone who reads the repository can forge cookies for any user including the Super-Admin. The fix loads the key from an environment variable and raises `RuntimeError` at startup if it is absent, preventing the application from running in an insecure state.

### V-02 — Insecure Direct Object Reference (High)
**File:** [app/account/routes.py](app/account/routes.py)  
**OWASP:** A01 — Broken Access Control | **CWE:** CWE-639

The account update, picture update, and delete routes accepted a URL `id` parameter without verifying it matched the authenticated user's own `id`. An attacker could modify any user's account by substituting a different `id`. Fixed with `abort(403)` when `id != current_user.id`.

### V-03 — Missing Role-Based Authorization on Admin Routes (High)
**File:** [app/dashboard/routes.py](app/dashboard/routes.py)  
**OWASP:** A01 — Broken Access Control | **CWE:** CWE-285

The `user_update`, `user_delete`, and `user_block` admin routes were decorated with `@login_required` only. Any authenticated user (including `user` and `author` roles) could reach these routes directly via URL. Fixed by adding `if current_user.type not in ("admin", "super_admin"): abort(403)` at the top of each affected function.

### V-04 — No Brute-Force Protection on Login (High)
**File:** [app/account/routes.py](app/account/routes.py)  
**OWASP:** A07 — Identification and Authentication Failures | **CWE:** CWE-307

The login endpoint had no rate limiting, allowing unlimited credential guessing. Two distinct flash messages (`"This email does not exist"` vs `"Incorrect password"`) also allowed email enumeration. Fixed by applying `@limiter.limit("5 per minute")` via Flask-Limiter and replacing both messages with the single generic response `"Invalid credentials, please try again."`.

### V-05 — No Password Complexity Enforcement (Medium)
**File:** [app/account/routes.py](app/account/routes.py)  
**OWASP:** A07 — Identification and Authentication Failures | **CWE:** CWE-521

Passwords of any length (including single characters) were accepted at signup. While PBKDF2-SHA256 hashing was applied, trivially weak passwords negate that protection. Fixed by enforcing minimum 8 characters, at least one uppercase letter, and at least one digit — validated server-side before the user record is created.

### V-06 — Stored XSS via CKEditor Post Body (High)
**File:** [app/dashboard/routes.py](app/dashboard/routes.py)  
**OWASP:** A03 — Injection | **CWE:** CWE-79

Blog post bodies were stored as raw HTML from CKEditor without server-side sanitisation. An Author-role user could inject `<script>` payloads that execute for every visitor to the post, including admins. Fixed by processing `form.body.data` through `bleach.clean()` with an allowlist of safe tags and attributes before writing to the database. Applied to both `submit_post` and `edit_post`.

### V-07 — Missing CSRF on JSON API Endpoints (Medium)
**Files:** [app/website/routes.py](app/website/routes.py), [app/templates/base.html](app/templates/base.html), [app/static/JS/app.js](app/static/JS/app.js)  
**OWASP:** A01 — Broken Access Control | **CWE:** CWE-352

Flask-WTF's CSRF protection only covers form submissions. The comment, reply, like, bookmark, and deletion endpoints accepted JSON `POST` requests with no CSRF validation, allowing cross-site request forgery. Fixed with a three-part approach: (1) `CSRFProtect` initialised globally, (2) JSON routes marked `@csrf.exempt` but manually validated via `validate_csrf(request.headers.get('X-CSRFToken'))`, and (3) a `<meta name="csrf-token">` tag and `getCsrfToken()` helper added to inject the token into every fetch call.

### V-08 — Unauthenticated Comment/Reply Deletion (High)
**File:** [app/website/routes.py](app/website/routes.py)  
**OWASP:** A01 — Broken Access Control | **CWE:** CWE-862

The `/delete_comment_or_reply/` endpoint had no `@login_required` decorator and no ownership check. Any unauthenticated request with a valid comment/reply ID could permanently delete content. Fixed by adding `@login_required` and verifying that `comment.user_id == current_user.id` (admins are exempt from the ownership check).

### V-09 — No Email Format Validation at Signup (Low)
**File:** [app/account/forms.py](app/account/forms.py)  
**OWASP:** A07 — Identification and Authentication Failures | **CWE:** CWE-1286

The signup form applied `DataRequired()` to the email field but did not enforce RFC-compliant format. Strings such as `"notanemail"` were accepted and stored. Fixed by adding `Email()` from `wtforms.validators` to the form field and a regex check in the signup route before the DB query.

### V-10 — No Session Timeout (Medium)
**File:** [app/config.py](app/config.py)  
**OWASP:** A07 — Identification and Authentication Failures | **CWE:** CWE-613

No session expiry was configured, leaving sessions open indefinitely on shared devices. The original code imported `timedelta` but never used it. Fixed by setting `PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)`, `SESSION_COOKIE_HTTPONLY = True` (blocks JavaScript access to the cookie), and `SESSION_COOKIE_SAMESITE = "Lax"` (mitigates CSRF via cross-origin requests).

### V-11 — Missing HTTP Security Headers (Medium)
**File:** [app/__init__.py](app/__init__.py)  
**OWASP:** A05 — Security Misconfiguration | **CWE:** CWE-693

No security headers were present on responses. Fixed via an `@app.after_request` hook that injects:
- `X-Content-Type-Options: nosniff` — prevents MIME sniffing
- `X-Frame-Options: SAMEORIGIN` — prevents clickjacking via iframes
- `Referrer-Policy: strict-origin-when-cross-origin` — limits URL leakage
- `Content-Security-Policy` — restricts resource origins to self + known CDNs

### V-12 — Client-Side File Size Validation Bypass (Medium)
**File:** [app/dashboard/routes.py](app/dashboard/routes.py)  
**OWASP:** A05 — Security Misconfiguration | **CWE:** CWE-434

The 1.5 MB image size limit was enforced using `form.picture_v_size.data` — a hidden form field populated by JavaScript. An attacker crafting a custom POST request could set this field to `0`, causing oversized files to bypass the check. Fixed by measuring the uploaded file server-side using `file.seek(0, 2); size = file.tell(); file.seek(0)` before the upload is processed.

### V-13 — No Rate Limiting on Contact Form (Low)
**File:** [app/website/routes.py](app/website/routes.py)  
**OWASP:** A05 — Security Misconfiguration | **CWE:** CWE-770

The contact form accepted unlimited unauthenticated POST requests, enabling spam, database flooding, and Gmail API exhaustion. Fixed by applying `@limiter.limit("5 per 10 minutes", methods=["POST"])` from Flask-Limiter.

### V-14 — Verbose Exception Disclosure (Medium) — Introduced
**File:** [app/website/routes.py](app/website/routes.py)  
**OWASP:** A05 — Security Misconfiguration | **CWE:** CWE-209

This vulnerability was deliberately introduced for assessment purposes (annotated with `[VULNERABILITY ADDED]` in the original source). The `except` block returned `str(e)` directly in the HTTP response, leaking SQLAlchemy internals (table names, column names, file paths). Fixed by logging the exception server-side with `logger.error()` and rendering a template with a generic user-facing error message.

---

## Testing Process

### Static Application Security Testing (SAST)

**Tool:** Bandit (`pip install bandit`)

```bash
bandit -r app/ -ll
```

Bandit was used to scan all Python source files for common security anti-patterns including hardcoded secrets, use of `assert`, `exec`, shell injection, and unsafe YAML/pickle usage. After all fixes were applied, no high-severity issues remained.

### Functional Security Testing

Three security features were manually tested:

**Test 1 — Brute-Force Rate Limit (V-04)**
- Procedure: Sent 6 consecutive POST requests to `/login` with incorrect credentials using a browser
- Expected: 6th request returns HTTP 429 Too Many Requests
- Result: Pass — Flask-Limiter blocked the request after 5 attempts within 60 seconds

**Test 2 — IDOR on Account Update (V-02)**
- Procedure: Logged in as regular user (id=4), navigated to `/dashboard/manage_account/update/1` (super_admin)
- Expected: HTTP 403 Forbidden
- Result: Pass — `abort(403)` triggered immediately when `id != current_user.id`

**Test 3 — Stored XSS via CKEditor (V-06)**
- Procedure: Logged in as author, submitted a post with body containing `<script>alert('XSS')</script>`
- Expected: Script tag stripped; body stored and rendered as plain text
- Result: Pass — bleach stripped the `<script>` tag; only the text content remained

### Tools Used
- **Bandit** — Python SAST
- **Browser DevTools** — Manual HTTP request inspection and header verification
- **curl** — Direct endpoint testing for CSRF and rate-limit verification

---

## Contributions and References

**Original Source Code:**  
bgtti. (2022). *blog_flask*. GitHub. https://github.com/bgtti/blog_flask  
License: MIT

**Security Libraries Added:**
- Flask-Limiter — https://flask-limiter.readthedocs.io
- bleach — https://bleach.readthedocs.io
- email-validator — https://pypi.org/project/email-validator

**Standards Referenced:**
- OWASP Top 10 (2021) — https://owasp.org/Top10/
- CWE/MITRE — https://cwe.mitre.org

**Frameworks Used:**
- Flask 3.1 — https://flask.palletsprojects.com
- Flask-WTF — https://flask-wtf.readthedocs.io
- Flask-Login — https://flask-login.readthedocs.io
- Flask-SQLAlchemy — https://flask-sqlalchemy.palletsprojects.com
- Flask-CKEditor — https://flask-ckeditor.readthedocs.io
- SQLite — https://www.sqlite.org

---

## Security Requirements Completion Table

| Req ID | Requirement | Status | % Complete |
|--------|------------|--------|------------|
| SR-01 | Secret key loaded from environment (not hardcoded) | Completed | 100 |
| SR-02 | IDOR prevention on all account self-service routes | Completed | 100 |
| SR-03 | Role-based access control on all admin routes | Completed | 100 |
| SR-04 | Brute-force rate limiting on login endpoint | Completed | 100 |
| SR-05 | Password complexity enforcement at signup | Completed | 100 |
| SR-06 | Server-side HTML sanitisation for CKEditor bodies | Completed | 100 |
| SR-07 | CSRF token validation for all JSON API endpoints | Completed | 100 |
| SR-08 | Authentication and ownership check on content deletion | Completed | 100 |
| SR-09 | RFC-compliant email validation at signup | Completed | 100 |
| SR-10 | Session timeout (30 min) with secure cookie flags | Completed | 100 |
| SR-11 | HTTP security headers on all responses (CSP, X-Frame, etc.) | Completed | 100 |
| SR-12 | Server-side file size enforcement on image uploads | Completed | 100 |
| SR-13 | Rate limiting on contact form endpoint | Completed | 100 |
| SR-14 | Generic error messages — no exception detail in HTTP responses | Completed | 100 |