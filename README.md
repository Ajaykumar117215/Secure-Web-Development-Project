# Secure Flask Blog Application
### National College of Ireland — MSc Cybersecurity (MSCCYB1)
### Secure Web Development — Continuous Assessment Project (Option A)

---

> **Original Source Repository:** https://github.com/bgtti/blog_flask  
> **License:** MIT  
> **Original Author:** bgtti  
> **Assessment Due Date:** 17 April 2026

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Base Code — Original Application](#2-base-code--original-application)
3. [Original Vulnerabilities Identified](#3-original-vulnerabilities-identified)
4. [Deliberately Introduced Vulnerability](#4-deliberately-introduced-vulnerability)
5. [Security Contributions — What Was Fixed and How](#5-security-contributions--what-was-fixed-and-how)
6. [Features and Security Objectives](#6-features-and-security-objectives)
7. [Project Structure](#7-project-structure)
8. [Setup and Installation Instructions](#8-setup-and-installation-instructions)
9. [Usage Guidelines](#9-usage-guidelines)
10. [Testing Process](#10-testing-process)
11. [Security Requirements Completion Table](#11-security-requirements-completion-table)
12. [Contributions and References](#12-contributions-and-references)

---

## 1. Project Overview

This project is submitted under **Option A** of the Secure Web Development CA. An existing open-source Flask blog application was selected from GitHub (bgtti/blog_flask), comprehensively audited for security vulnerabilities, and hardened by implementing fourteen security fixes in the student's own code.

The application is a multi-user travel blog built with Python/Flask, SQLite, and Flask-SQLAlchemy. It supports four distinct user roles (super_admin, admin, author, user) and provides full CRUD operations on blog posts, user accounts, comments, likes, bookmarks, and contact messages.

**Primary Security Focus:**
The original codebase contained significant security weaknesses across authentication, authorisation, input validation, session management, and server configuration — representing real-world vulnerabilities from OWASP Top 10 (2021) categories A01 through A07. All security improvements were implemented entirely by the student.

---

## 2. Base Code — Original Application

**Repository:** https://github.com/bgtti/blog_flask  
**License:** MIT — free to use, modify, and distribute with attribution  
**Technology Stack:** Python 3, Flask 2.x, SQLite, SQLAlchemy, Flask-Login, Flask-WTF, CKEditor, Werkzeug

### Original Functionalities (Before Security Work)

The original application provided a working travel blog platform with:

| Feature | Description |
|---------|-------------|
| User Registration & Login | Email/password signup with PBKDF2-SHA256 hashing |
| Role-Based Dashboards | Separate dashboards for user, author, admin, super_admin |
| Blog Post Management | Authors submit posts; admins approve/reject before publication |
| Comment & Reply System | Logged-in users can comment and reply on posts |
| Likes & Bookmarks | Users can like and bookmark posts via JavaScript fetch calls |
| Profile Management | Users can update name, email, biography, and profile picture |
| Admin User Management | Admins can update, block, and delete user accounts |
| Contact Form | Public contact form that saves messages to the database and sends email |
| Theme-Based Navigation | Posts organised under four content themes |

### What the Original Code Lacked

The original codebase was intentionally selected because security was **not considered** during its development. The author's own README acknowledged one known issue (XSS via CKEditor) but left the majority of vulnerabilities unaddressed. There was no rate limiting, no session expiry, no HTTP security headers, no role enforcement on sensitive routes, and the application's secret key was hardcoded in source.

---

## 3. Original Vulnerabilities Identified

A full audit of the codebase identified **thirteen pre-existing vulnerabilities** before any student work began. Each was mapped to the OWASP Top 10 (2021) and CWE/MITRE standards.

| ID | Vulnerability | File | OWASP | CWE | Severity |
|----|--------------|------|-------|-----|----------|
| V-01 | Hardcoded `SECRET_KEY = "myFlaskApp4Fun"` | `app/config.py` | A05 | CWE-798 | Critical |
| V-02 | IDOR — account update/delete accepts any user `id` in URL | `app/account/routes.py` | A01 | CWE-639 | High |
| V-03 | Admin routes (`user_update`, `user_delete`, `user_block`) had no role check | `app/dashboard/routes.py` | A01 | CWE-285 | High |
| V-04 | No rate limiting on login — unlimited brute-force attempts allowed | `app/account/routes.py` | A07 | CWE-307 | High |
| V-05 | No password complexity — single character passwords accepted at signup | `app/account/routes.py` | A07 | CWE-521 | Medium |
| V-06 | Stored XSS — CKEditor HTML body stored without server-side sanitisation | `app/dashboard/routes.py` | A03 | CWE-79 | High |
| V-07 | No CSRF on JSON API endpoints (comment, like, bookmark, delete) | `app/website/routes.py` | A01 | CWE-352 | Medium |
| V-08 | Comment/reply deletion required no authentication and no ownership check | `app/website/routes.py` | A01 | CWE-862 | High |
| V-09 | No email format validation at signup — any string accepted as email | `app/account/forms.py` | A07 | CWE-1286 | Low |
| V-10 | No session timeout — sessions lived indefinitely with no expiry | `app/config.py` | A07 | CWE-613 | Medium |
| V-11 | No HTTP security headers — no CSP, X-Frame-Options, or HSTS | `app/__init__.py` | A05 | CWE-693 | Medium |
| V-12 | Image upload size enforced using client-supplied form field — trivially bypassed | `app/dashboard/routes.py` | A05 | CWE-434 | Medium |
| V-13 | No rate limiting on contact form — open to spam and resource exhaustion | `app/website/routes.py` | A05 | CWE-770 | Low |

---

## 4. Deliberately Introduced Vulnerability

In addition to the thirteen pre-existing vulnerabilities, **one vulnerability (V-14) was deliberately introduced** into the codebase by the student for assessment purposes. The change is clearly annotated in the source code with a `[VULNERABILITY ADDED]` comment and is documented here with full transparency.

| ID | Vulnerability | File | OWASP | CWE | Severity |
|----|--------------|------|-------|-----|----------|
| V-14 | **ADDED** — Verbose exception disclosure: `return str(e)` in contact form error handler | `app/website/routes.py` | A05 | CWE-209 | Medium |

**What was changed:**

```python
# Original safe code (before introduction):
except:
    return "There was an error adding message to the database."

# Vulnerable code introduced by student:
except Exception as e:
    # [VULNERABILITY ADDED]: Exposes full internal exception details to the client.
    return f"There was an error adding message to the database: {str(e)}"
```

**Why it is dangerous:** When a database error occurs (e.g., a schema constraint violation), the full SQLAlchemy exception message — including SQL statements, table names, column names, and internal file paths — is returned to the browser in plain text. An attacker can deliberately trigger the error and use the leaked schema details to craft more targeted injection or enumeration attacks (CWE-209).

This vulnerability was introduced to demonstrate understanding of information disclosure and to practice the identification and remediation of server-side error handling issues.

---

## 5. Security Contributions — What Was Fixed and How

All fourteen vulnerabilities were remediated. The following describes each fix in detail.

---

### V-01 — Hardcoded Secret Key
**File:** `app/config.py`

The original `SECRET_KEY = "myFlaskApp4Fun"` was replaced with an environment variable lookup. The application now raises a `RuntimeError` at startup if the key is absent, preventing it from running in an insecure state. A cryptographically random 64-character hex key was generated using Python's `secrets` module and stored in a `.env` file excluded from version control.

```python
# Before
SECRET_KEY = "myFlaskApp4Fun"

# After
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY environment variable is not set.")
```

---

### V-02 — Insecure Direct Object Reference (IDOR)
**File:** `app/account/routes.py`

Three routes (`update_own_acct_info`, `update_own_acct_picture`, `delete_own_acct`) accepted a URL `id` parameter and operated on it without verifying it matched the authenticated user. An `abort(403)` guard was added at the top of each route.

```python
# After — applied to all three routes
if id != current_user.id:
    abort(403)
```

---

### V-03 — Missing Role-Based Authorization on Admin Routes
**File:** `app/dashboard/routes.py`

`user_update`, `user_delete`, and `user_block` were protected only by `@login_required`. Any role — including regular users and authors — could invoke these routes by navigating to the URL directly. A role check was added to each route.

```python
# After — applied to all three admin routes
if current_user.type not in ("admin", "super_admin"):
    abort(403)
```

---

### V-04 — No Brute-Force Protection on Login
**File:** `app/account/routes.py`

Flask-Limiter was added to the project. The `/login` route was decorated with `@limiter.limit("5 per minute")`, blocking further attempts after five failures within 60 seconds per IP address. The two distinct error messages that allowed email enumeration (`"This email does not exist"` vs `"Incorrect password"`) were replaced with a single generic response.

```python
# After
@limiter.limit("5 per minute")
def login():
    if not the_user or not check_password_hash(the_user.password, password):
        flash("Invalid credentials, please try again.")
```

---

### V-05 — No Password Complexity Enforcement
**File:** `app/account/routes.py`

Server-side validation was added to the signup route before the user record is created. Three checks are enforced: minimum length of 8 characters, at least one uppercase letter, and at least one digit.

```python
# After
if len(password) < 8:
    flash("Password must be at least 8 characters.")
if not any(c.isupper() for c in password):
    flash("Password must contain at least one uppercase letter.")
if not any(c.isdigit() for c in password):
    flash("Password must contain at least one digit.")
```

---

### V-06 — Stored XSS via CKEditor
**Files:** `app/dashboard/routes.py`

The `bleach` library was added to sanitise HTML from the CKEditor rich-text editor before it is written to the database. An allowlist of safe tags and attributes is defined; all other tags are stripped. This fix was applied to both the `submit_post` and `edit_post` functions.

```python
# After
ALLOWED_TAGS = ['p', 'b', 'i', 'u', 'em', 'strong', 'a', 'ul', 'ol',
                'li', 'br', 'h2', 'h3', 'h4', 'blockquote', 'pre', 'code', 'img', 'span']
ALLOWED_ATTRS = {'a': ['href', 'title', 'rel'], 'img': ['src', 'alt', 'width', 'height']}
body_clean = bleach.clean(form.body.data, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS, strip=True)
post = Blog_Posts(..., body=body_clean, ...)
```

**Verified result:** The payload `<script>alert('XSS!')</script>` submitted via the form is stored in the database as `alert('XSS!')` — the script tags are stripped and the text content is rendered as harmless plain text with no JavaScript execution.

---

### V-07 — Missing CSRF on JSON API Endpoints
**Files:** `app/extensions.py`, `app/__init__.py`, `app/website/routes.py`, `app/templates/base.html`, `app/static/JS/app.js`

A three-part solution was implemented:

1. `CSRFProtect` from Flask-WTF was initialised globally — covering all WTForms-based form POST requests automatically.
2. JSON API endpoints (`/comment_post`, `/delete_comment_or_reply`, `/like_post`, `/bookmark_post`) were marked `@csrf.exempt` to opt out of the automatic form-body check, and instead manually validate the `X-CSRFToken` request header using `validate_csrf()`.
3. A `<meta name="csrf-token">` tag was added to `base.html`, and a `getCsrfToken()` helper function was added to `app.js` to inject the token into every state-changing fetch call.

```python
# Server-side (website/routes.py)
@csrf.exempt
@login_required
def post_comment(index):
    try:
        validate_csrf(request.headers.get('X-CSRFToken'))
    except ValidationError:
        return make_response(jsonify({"message": "CSRF token missing or invalid"}), 403)
```

```javascript
// Client-side (app.js)
function getCsrfToken() {
    return document.querySelector('meta[name="csrf-token"]').getAttribute('content');
}
// All fetch calls include: 'X-CSRFToken': getCsrfToken()
```

All ten plain HTML form templates that were missing the CSRF token were also updated with `<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">`.

---

### V-08 — Unauthenticated Comment/Reply Deletion
**File:** `app/website/routes.py`

`@login_required` was added to the `/delete_comment_or_reply/` route. An ownership check was added to verify that the authenticated user is either the author of the comment/reply or holds an admin role before deletion is permitted.

```python
# After
@login_required
def post_delete_comment(index):
    ...
    if current_user.type not in ("admin", "super_admin") and comment.user_id != current_user.id:
        return make_response(jsonify({"message": "Unauthorized"}), 403)
```

---

### V-09 — No Email Format Validation at Signup
**Files:** `app/account/forms.py`, `app/account/routes.py`

The `Email()` validator from WTForms was added to the `The_Accounts` form class to enforce RFC-compliant email format on the account management form. A regex check was also added in the signup route, which reads directly from `request.form` rather than from the WTForms instance.

```python
# forms.py — After
from wtforms.validators import DataRequired, Length, Email
email = StringField("Email", validators=[DataRequired(), Email()])

# routes.py — After
if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
    flash("Please enter a valid email address.")
```

---

### V-10 — No Session Timeout
**File:** `app/config.py`

Three session security settings were added to the `Config` class. Sessions now expire after 30 minutes. The `HttpOnly` flag prevents JavaScript from accessing the session cookie, and `SameSite=Lax` restricts the cookie from being sent in cross-site requests, mitigating CSRF at the cookie level.

```python
PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
```

---

### V-11 — Missing HTTP Security Headers
**File:** `app/__init__.py`

An `@app.after_request` hook was added to the application factory to inject four security headers on every HTTP response.

```python
@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net "
        "https://cdn.ckeditor.com; ..."
    )
    return response
```

| Header | Protection |
|--------|-----------|
| `X-Content-Type-Options: nosniff` | Prevents MIME-type sniffing attacks |
| `X-Frame-Options: SAMEORIGIN` | Prevents clickjacking via `<iframe>` embedding |
| `Referrer-Policy` | Limits URL information leaked to external sites |
| `Content-Security-Policy` | Restricts which origins may load scripts, styles, and images |

---

### V-12 — Client-Side File Size Validation Bypass
**File:** `app/dashboard/routes.py`

The original code checked image size using `form.picture_v_size.data` — a hidden input field populated by JavaScript and trivially falsified by an attacker. The fix replaces this with a server-side measurement using Python's file seek/tell API before the image is processed.

```python
# Before (vulnerable — client-supplied value)
if form.picture_v.data and int(form.picture_v_size.data) < 1500000:

# After (server-side measurement)
def get_server_file_size(file_storage):
    file_storage.seek(0, 2)
    size = file_storage.tell()
    file_storage.seek(0)
    return size

if form.picture_v.data and get_server_file_size(form.picture_v.data) < 1_500_000:
```

---

### V-13 — No Rate Limiting on Contact Form
**File:** `app/website/routes.py`

Flask-Limiter was applied to the contact form endpoint, restricting POST requests to 5 per 10 minutes per IP address. This prevents automated spam, database flooding, and Gmail API rate-limit exhaustion.

```python
@limiter.limit("5 per 10 minutes", methods=["POST"])
def contact():
```

---

### V-14 — Verbose Exception Disclosure (Introduced + Fixed)
**File:** `app/website/routes.py`

The deliberately introduced vulnerability (`return f"... {str(e)}"`) was remediated by logging the full exception server-side using Python's `logging` module and rendering a generic error page to the client with no internal details exposed.

```python
# After
except Exception as e:
    logger.error("Contact form DB/email error: %s", e, exc_info=True)
    db.session.rollback()
    return render_template('website/contact.html', msg_sent=False, error=True, ...)
```

---

## 6. Features and Security Objectives

### Application Features

| Feature | Roles |
|---------|-------|
| Register / Login / Logout | All |
| View and read blog posts | All (including guests) |
| Like and bookmark posts | Authenticated users |
| Comment and reply on posts | Authenticated users |
| Delete own comments/replies | Authenticated users (own content only) |
| Update profile, picture, delete account | Authenticated users (own account only) |
| Submit new blog posts | Author, Admin, Super Admin |
| Edit and delete own posts | Author (own posts), Admin (all posts) |
| Approve or reject posts | Admin, Super Admin |
| Manage all users (update/block/delete) | Admin, Super Admin |
| Contact form | All (including guests) |

### Security Objectives Achieved

- Environment-based secret management preventing session forgery
- Role-based access control enforced at route level for all sensitive operations
- Ownership validation preventing horizontal privilege escalation
- Brute-force protection on authentication endpoint
- Strong password policy enforced server-side
- Server-side HTML sanitisation preventing stored XSS
- Full CSRF protection across form and JSON API request paths
- Authentication required on all state-modifying content operations
- Input validation on user-supplied email addresses
- Session expiry and secure cookie attributes
- HTTP security headers on every response
- Server-side file size enforcement on all image upload paths
- Rate limiting on public-facing form endpoints
- Generic error responses with server-side exception logging

---

## 7. Project Structure

```
blog_flask/
│
├── app/
│   ├── __init__.py              # App factory — extension init, security headers (V-11)
│   ├── config.py                # Config class — SECRET_KEY from env (V-01), session (V-10)
│   ├── extensions.py            # SQLAlchemy, CKEditor, LoginManager, CSRFProtect, Limiter
│   │
│   ├── account/
│   │   ├── forms.py             # The_Accounts form — Email() validator (V-09)
│   │   ├── routes.py            # Login rate-limit (V-04), IDOR checks (V-02),
│   │   │                        # password complexity (V-05), email regex (V-09)
│   │   └── helpers.py           # Password hashing utility
│   │
│   ├── dashboard/
│   │   ├── routes.py            # Role guards (V-03), bleach sanitisation (V-06),
│   │   │                        # server-side file size enforcement (V-12)
│   │   └── forms.py             # The_Posts WTForm for post submission/edit
│   │
│   ├── website/
│   │   ├── routes.py            # CSRF on JSON APIs (V-07), auth+ownership on delete (V-08),
│   │   │                        # rate-limited contact (V-13), generic error (V-14)
│   │   └── contact.py           # SMTP email helper
│   │
│   ├── models/                  # SQLAlchemy ORM models
│   │   ├── user.py              # Blog_User model
│   │   ├── posts.py             # Blog_Posts model
│   │   ├── comments.py          # Blog_Comments, Blog_Replies models
│   │   ├── likes.py             # Blog_Likes model
│   │   ├── bookmarks.py         # Blog_Bookmarks model
│   │   ├── contact.py           # Blog_Contact model
│   │   └── stats.py             # Blog_Stats model
│   │
│   ├── static/
│   │   ├── JS/app.js            # getCsrfToken() + X-CSRFToken in all fetch calls (V-07)
│   │   ├── CSS/styles.css       # Application stylesheet
│   │   ├── Pictures_Users/      # User profile pictures
│   │   └── Pictures_Posts/      # Blog post images
│   │
│   └── templates/
│       ├── base.html            # Base layout — CSRF meta tag (V-07)
│       ├── account/             # Login, signup, dashboard, account management templates
│       ├── dashboard/           # Admin/author post and user management templates
│       └── website/             # Public-facing pages (home, posts, about, contact)
│
├── instance/
│   └── admin.db                 # SQLite database (auto-created on first run)
│
├── create_db.py                 # Seeds database with dummy accounts and posts
├── run.py                       # Application entry point
├── requirements_new.txt         # Verified dependency list (Python 3.10+ compatible)
├── .env                         # Environment variables — NOT committed to version control
├── .gitignore                   # Excludes .env, instance/, venv/, __pycache__/
├── Vulnerabilities.md           # Full vulnerability audit with OWASP/CWE references
└── Final_Readme.md              # This file
```

---

## 8. Setup and Installation Instructions

### Prerequisites

- Python 3.10 or higher — verify: `python --version`
- pip — verify: `pip --version`
- Git — verify: `git --version`

### Step 1 — Clone the Repository

```bash
git clone <your-github-repo-url>
cd blog_flask
```

### Step 2 — Create and Activate a Virtual Environment

```bash
python -m venv venv

# Windows (PowerShell)
venv\Scripts\Activate.ps1

# Windows (Command Prompt)
venv\Scripts\activate.bat

# macOS / Linux
source venv/bin/activate
```

The terminal prompt will show `(venv)` when the environment is active.

### Step 3 — Install Dependencies

```bash
pip install -r requirements_new.txt
```

> **Note:** Use `requirements_new.txt` — not the original `requirements.txt`. The original file pins versions incompatible with Python 3.10+. The new file includes three additional security packages: `flask-limiter`, `bleach`, and `email-validator`.

### Step 4 — Create the `.env` File

Create a file named `.env` in the project root (same directory as `run.py`):

```
SECRET_KEY=<generate using the command below>
EMAIL_ADDRESS=your_gmail@gmail.com
EMAIL_PASSWORD=your_gmail_app_password
```

**Generate a secure SECRET_KEY:**

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

Copy the output and paste it as the value for `SECRET_KEY`.

> **Important:** `SECRET_KEY` is required. The application will raise a `RuntimeError` and refuse to start without it. The `.env` file must never be committed to version control — it is listed in `.gitignore`.

> `EMAIL_ADDRESS` and `EMAIL_PASSWORD` are optional. The contact form saves messages to the database regardless; email delivery will fail silently if these are not set.

### Step 5 — Run the Application

```bash
python run.py
```

On first run the SQLite database is created at `instance/admin.db` and populated with dummy data automatically (5 test users, sample posts, comments, and themes).

### Step 6 — Open in Browser

```
http://127.0.0.1:5000
```

### Resetting the Database

```bash
# Windows
rmdir /s /q instance

# macOS / Linux
rm -rf instance/

python run.py
```

---

## 9. Usage Guidelines

### Pre-loaded Test Accounts

| Role | Email | Password | Permissions |
|------|-------|----------|-------------|
| Super Admin | `super@admin` | `admin123` | Full access including managing admins |
| Admin | `r@r` | `user123` | Manage users and approve posts |
| Author | `e@e` | `user123` | Submit and edit own posts |
| Regular User | `j@m` | `user123` | Read, comment, like, bookmark |

> **Note:** Pre-loaded passwords were set before the password complexity rule (V-05) was introduced. New accounts created through the signup form must satisfy the current requirements: minimum 8 characters, at least one uppercase letter, at least one digit.

### Key Navigation Paths

| Page | URL | Access |
|------|-----|--------|
| Home | `/` | Public |
| All Posts | `/all/0` | Public |
| About | `/about/` | Public |
| Contact | `/contact/` | Public |
| Login | `/login` | Public |
| Sign Up | `/signup` | Public |
| User Dashboard | `/dashboard` | Authenticated |
| Account Settings | `/dashboard/manage_account` | Authenticated |
| Submit Post | `/dashboard/submit_new_post` | Author+ |
| Admin Users | `/dashboard/manage_users` | Admin+ |
| Admin Posts | `/dashboard/manage_posts` | Admin+ |

### User Role Capability Matrix

| Capability | guest | user | author | admin | super_admin |
|------------|-------|------|--------|-------|-------------|
| View posts | Yes | Yes | Yes | Yes | Yes |
| Comment / Like / Bookmark | No | Yes | Yes | Yes | Yes |
| Delete own comments | No | Yes | Yes | Yes | Yes |
| Submit posts | No | No | Yes | Yes | Yes |
| Approve posts | No | No | No | Yes | Yes |
| Manage users | No | No | No | Yes | Yes |
| Delete super_admin | No | No | No | No | No |

---

## 10. Testing Process

### Static Application Security Testing (SAST)

**Tool:** Bandit v1.7+

Bandit was used to scan all Python source files for common security anti-patterns including hardcoded secrets, use of `assert`, `exec`, shell injection, unsafe YAML/pickle usage, and weak cryptography.

```bash
pip install bandit
bandit -r app/ -ll
```

After all security fixes were applied, Bandit returned no high-severity issues. Medium-severity findings related to use of `except:` bare clauses in original non-security code were noted but are outside the scope of this project's security improvements.

---

### Functional Security Test 1 — Brute-Force Rate Limiting (V-04)

**Feature tested:** Login rate limit (5 attempts per minute per IP)

**Procedure:**
```powershell
1..6 | ForEach-Object {
    $r = Invoke-WebRequest -Uri "http://127.0.0.1:5000/login" `
        -Method POST -Body "email=wrong@wrong.com&password=bad&csrf_token=" `
        -MaximumRedirection 0 -ErrorAction SilentlyContinue
    Write-Host "Attempt $_: HTTP $($r.StatusCode)"
}
```

**Expected Result:**

| Attempt | HTTP Status | Meaning |
|---------|-------------|---------|
| 1–5 | 302 | Redirected back to login (credentials rejected) |
| 6 | 429 | Too Many Requests — rate limit enforced |

**Actual Result:** Passed. The 6th request returned HTTP 429.

**Unified error message confirmed:** Both wrong-email and wrong-password scenarios now return `"Invalid credentials, please try again."` — no email enumeration possible.

---

### Functional Security Test 2 — IDOR Prevention (V-02)

**Feature tested:** Account update route rejects requests targeting another user's ID

**Procedure:**
1. Log in as regular user `j@m` (ID: 4)
2. Navigate directly to `http://127.0.0.1:5000/dashboard/manage_account/update/1` (super_admin ID)

**Expected Result:** HTTP 403 Forbidden

**Actual Result:** Passed. The `abort(403)` guard fired immediately. The super_admin's account information was not accessible.

**Additional checks passed:**
- `/dashboard/manage_account/update_picture/1` → 403
- `/dashboard/manage_account/delete/1` → 403
- `/dashboard/manage_account/update/4` (own account) → 200 (loads correctly)

---

### Functional Security Test 3 — Stored XSS Sanitisation (V-06)

**Feature tested:** CKEditor body sanitisation prevents stored script injection

**Procedure:**
1. Log in as author `e@e`
2. Navigate to `/dashboard/submit_new_post`
3. In the Body field (Source mode), submit:
   ```html
   <p>Normal text</p><script>alert('XSS!')</script><b>Bold text</b>
   ```
4. After admin approval, view the published post

**Expected Result:** No alert box fires. Body stored as `<p>Normal text</p>alert('XSS!')<b>Bold text</b>`

**Actual Result:** Passed. Verified directly in SQLite database using DB Browser. The `<script>` and `</script>` tags were stripped by `bleach.clean()`. The JavaScript function call text `alert('XSS!')` remains as inert plain text — it renders on the page but does not execute.

---

### Summary of Key Testing Findings

| Test | Tool | Result | Notes |
|------|------|--------|-------|
| Bandit SAST scan | Bandit | No high-severity issues | Medium bare-except findings pre-exist in original code |
| Brute-force rate limit | Browser / PowerShell | Pass | HTTP 429 after 5 attempts |
| IDOR access control | Browser | Pass | HTTP 403 for cross-user ID access |
| Stored XSS | Browser + DB Browser | Pass | Script tags stripped; plain text stored |
| CSRF on JSON API | Browser console | Pass | HTTP 403 without X-CSRFToken header |
| Session cookie flags | Browser DevTools | Pass | HttpOnly=True, SameSite=Lax confirmed |
| Security headers | PowerShell curl | Pass | All 4 headers present on every response |
| Password complexity | Browser | Pass | Weak passwords rejected with specific guidance |

---

## 11. Security Requirements Completion Table

| Req ID | Requirement | OWASP | Status | Completion |
|--------|------------|-------|--------|------------|
| SR-01 | Secret key loaded from environment variable | A05 | Completed | 100% |
| SR-02 | IDOR prevention on all account self-service routes | A01 | Completed | 100% |
| SR-03 | Role-based access control on all admin-mutating routes | A01 | Completed | 100% |
| SR-04 | Rate limiting on login endpoint (5/min per IP) | A07 | Completed | 100% |
| SR-05 | Password complexity enforcement at signup | A07 | Completed | 100% |
| SR-06 | Server-side HTML sanitisation of CKEditor post bodies | A03 | Completed | 100% |
| SR-07 | CSRF token validation for all JSON API endpoints | A01 | Completed | 100% |
| SR-08 | Authentication and ownership check on content deletion | A01 | Completed | 100% |
| SR-09 | RFC-compliant email format validation at signup | A07 | Completed | 100% |
| SR-10 | Session timeout (30 min) with secure cookie attributes | A07 | Completed | 100% |
| SR-11 | HTTP security headers on every response | A05 | Completed | 100% |
| SR-12 | Server-side enforcement of image upload size limit | A05 | Completed | 100% |
| SR-13 | Rate limiting on contact form (5 per 10 min per IP) | A05 | Completed | 100% |
| SR-14 | Generic error messages with server-side exception logging | A05 | Completed | 100% |

**Total: 14 / 14 security requirements implemented — 100% completion**

---

## 12. Contributions and References

### Original Source Code

bgtti. (2022). *blog_flask* [Source code]. GitHub. https://github.com/bgtti/blog_flask  
Licensed under the MIT License. Used as base code for security improvement under Option A of the NCI Secure Web Development CA.

### Security Libraries Added

| Library | Version | Purpose |
|---------|---------|---------|
| Flask-Limiter | 4.1.1 | Rate limiting on login and contact form endpoints |
| bleach | 6.3.0 | Server-side HTML sanitisation to prevent stored XSS |
| email-validator | 2.3.0 | Required by WTForms `Email()` validator |

### Frameworks and Tools

| Technology | Purpose |
|-----------|---------|
| Flask 3.1 | Web application framework |
| Flask-WTF 1.2 | WTForms integration with CSRF protection |
| Flask-Login 0.6 | Session management and `@login_required` decorator |
| Flask-SQLAlchemy 3.1 | ORM for SQLite database access |
| Flask-CKEditor 1.0 | Rich-text editor integration |
| Werkzeug 3.1 | Password hashing (PBKDF2-SHA256) and file utilities |
| Bandit | Static Application Security Testing (SAST) |
| DB Browser for SQLite | Database inspection and verification |
| Python `secrets` module | Cryptographically secure key generation |