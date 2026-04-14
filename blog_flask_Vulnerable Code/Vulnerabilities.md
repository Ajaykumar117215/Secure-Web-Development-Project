# Vulnerabilities — blog_flask

**Source Repository:** https://github.com/bgtti/blog_flask  
**Technology Stack:** Python 3, Flask 2.2.2, SQLite, SQLAlchemy, Flask-Login, WTForms, CKEditor  
**Assessment Date:** 2026-04-14  
**Standard References:** OWASP Top 10 (2021), CWE/MITRE

---

## How to Run the Application

### Prerequisites
- Python 3.x — verify with `python --version`
- pip — verify with `pip --version`

### Step 1 — Navigate to the project folder

```bash
cd "d:\Ajay Ireland - Option A\blog_flask"
```

### Step 2 — Create and activate a virtual environment

```bash
python -m venv venv
venv\Scripts\activate
```

The terminal prompt will show `(venv)` when active.

### Step 3 — Install dependencies

> **Note:** The original `requirements.txt` contains old pinned versions incompatible with Python 3.14+. Use `requirements_new.txt` instead, which contains verified working versions.

```bash
pip install -r requirements_new.txt
```

### Step 4 — Create the `.env` file

Create a file named `.env` inside the `blog_flask` folder (same level as `run.py`):

```
EMAIL_ADDRESS=your_gmail@gmail.com
EMAIL_PASSWORD=your_gmail_app_password
```

The contact form requires these to send emails. The rest of the application runs without them.

### Step 5 — Run the application

```bash
python run.py
```

On first run this automatically creates the SQLite database at `instance/admin.db` and populates it with dummy data.

### Step 6 — Open in browser

```
http://127.0.0.1:5000
```

### Pre-loaded Test Accounts

| Role | Email | Password |
|------|-------|----------|
| Super Admin | `super@admin` | `admin123` |
| Admin | `r@r` | `user123` |
| Author | `e@e` | `user123` |
| Regular User | `j@m` | `user123` |

### Reset the Database

Delete the `instance/` folder and re-run `run.py` to rebuild from scratch:

```bash
rmdir /s /q instance
python run.py
```

---

## Table of Contents

1. [V-01 — Hardcoded Secret Key](#v-01--hardcoded-secret-key)
2. [V-02 — Insecure Direct Object Reference (IDOR) on Account Update](#v-02--insecure-direct-object-reference-idor-on-account-update)
3. [V-03 — Missing Role-Based Authorization on Admin Dashboard Routes](#v-03--missing-role-based-authorization-on-admin-dashboard-routes)
4. [V-04 — No Brute Force / Rate Limiting on Login](#v-04--no-brute-force--rate-limiting-on-login)
5. [V-05 — No Password Complexity Enforcement](#v-05--no-password-complexity-enforcement)
6. [V-06 — Stored Cross-Site Scripting (XSS) via CKEditor Post Body](#v-06--stored-cross-site-scripting-xss-via-ckeditor-post-body)
7. [V-07 — Missing CSRF Protection on JSON API Endpoints](#v-07--missing-csrf-protection-on-json-api-endpoints)
8. [V-08 — Unauthenticated Comment and Reply Deletion](#v-08--unauthenticated-comment-and-reply-deletion)
9. [V-09 — No Email Format Validation at Signup](#v-09--no-email-format-validation-at-signup)
10. [V-10 — No Session Timeout Configuration](#v-10--no-session-timeout-configuration)
11. [V-11 — Missing HTTP Security Headers](#v-11--missing-http-security-headers)
12. [V-12 — Client-Side File Size Validation Bypass on Image Upload](#v-12--client-side-file-size-validation-bypass-on-image-upload)
13. [V-13 — No Rate Limiting on Contact Form (Spam / Abuse)](#v-13--no-rate-limiting-on-contact-form-spam--abuse)
14. [V-14 — ⚠️ ADDED — Verbose Exception Disclosure on Contact Form Error](#v-14--️-added--verbose-exception-disclosure-on-contact-form-error)

---

## V-01 — Hardcoded Secret Key

| Field            | Detail |
|------------------|--------|
| **File**         | `app/config.py` — Line 6 |
| **OWASP**        | A05:2021 – Security Misconfiguration |
| **CWE**          | CWE-798: Use of Hard-coded Credentials |
| **Severity**     | Critical |

**Description:**  
The Flask `SECRET_KEY` is set to a static, hardcoded string `"myFlaskApp4Fun"` directly in the source code. Flask uses this key to cryptographically sign session cookies. An attacker with access to the repository can forge arbitrary session tokens, impersonate any user (including the Super-Admin), and bypass all authentication controls.

**Affected Code:**
```python
# app/config.py — Line 6
SECRET_KEY = "myFlaskApp4Fun"
```

**Fix:**  
Load the secret key from an environment variable and enforce its presence at startup:
```python
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY environment variable is not set.")
```

---

## V-02 — Insecure Direct Object Reference (IDOR) on Account Update

| Field            | Detail |
|------------------|--------|
| **File**         | `app/account/routes.py` — Lines 122–145 |
| **OWASP**        | A01:2021 – Broken Access Control |
| **CWE**          | CWE-639: Authorization Bypass Through User-Controlled Key |
| **Severity**     | High |

**Description:**  
The `/dashboard/manage_account/update/<int:id>` route accepts a user-controlled `id` parameter and updates the corresponding user record without verifying that the authenticated user owns that record. Any logged-in user can update any other user's name, email, and biography by substituting a different `id` in the URL — including admin accounts.

**Affected Code:**
```python
# app/account/routes.py — Lines 122–145
@account.route("/dashboard/manage_account/update/<int:id>", methods=["GET", "POST"])
@login_required
def update_own_acct_info(id):
    user_at_hand = Blog_User.query.get_or_404(id)
    # No check: id == current_user.id
    if form.validate_on_submit():
        user_at_hand.name = form.username.data
        ...
```

**Fix:**  
Reject the request if the target `id` does not match the authenticated user:
```python
if id != current_user.id:
    abort(403)
```

---

## V-03 — Missing Role-Based Authorization on Admin Dashboard Routes

| Field            | Detail |
|------------------|--------|
| **File**         | `app/dashboard/routes.py` — Lines 38, 98, 162 |
| **OWASP**        | A01:2021 – Broken Access Control |
| **CWE**          | CWE-285: Improper Authorization |
| **Severity**     | High |

**Description:**  
Several sensitive admin-only routes — `user_update`, `user_delete`, and `user_block` — are decorated with `@login_required` only. No check confirms that the current user holds an admin or super_admin role. A regular `user` or `author` who knows the URL can invoke these routes directly and modify or delete other user accounts.

The read-only `users_table` route at Line 26 does perform a role check, but the mutating routes beneath it do not, creating an inconsistent authorization boundary.

**Affected Code:**
```python
# app/dashboard/routes.py — Line 38
@dashboard.route("/dashboard/manage_users/update/<int:id>", methods=["GET", "POST"])
@login_required
def user_update(id):
    # No role check — any authenticated user can reach this route
```

**Fix:**  
Add a role guard at the top of each affected route:
```python
if current_user.type not in ("admin", "super_admin"):
    abort(403)
```

---

## V-04 — No Brute Force / Rate Limiting on Login

| Field            | Detail |
|------------------|--------|
| **File**         | `app/account/routes.py` — Lines 58–80 |
| **OWASP**        | A07:2021 – Identification and Authentication Failures |
| **CWE**          | CWE-307: Improper Restriction of Excessive Authentication Attempts |
| **Severity**     | High |

**Description:**  
The `/login` route imposes no limit on failed authentication attempts. An attacker can make an unlimited number of requests to the endpoint and enumerate valid email addresses (distinct error messages are returned for unknown email vs. wrong password) and perform credential-stuffing or dictionary attacks without restriction.

**Affected Code:**
```python
# app/account/routes.py — Lines 64–70
if not the_user:
    flash("This email does not exist in our database.")  # confirms email non-existence
elif not check_password_hash(the_user.password, password):
    flash("Incorrect password, please try again.")       # confirms email existence
```

**Fix:**  
Implement account lockout after N failed attempts, use `flask-limiter` for rate limiting, and replace the distinct error messages with a single generic response such as `"Invalid credentials."`.

---

## V-05 — No Password Complexity Enforcement

| Field            | Detail |
|------------------|--------|
| **File**         | `app/account/routes.py` — Line 41, `app/account/forms.py` |
| **OWASP**        | A07:2021 – Identification and Authentication Failures |
| **CWE**          | CWE-521: Weak Password Requirements |
| **Severity**     | Medium |

**Description:**  
At signup, the only constraint on the password field is that it must be present (`DataRequired()`). Single-character passwords such as `"a"` are accepted and stored. There is no minimum length, no character class requirement, and no confirmation field. While PBKDF2-SHA256 hashing is applied, a trivially weak password negates that protection.

**Affected Code:**
```python
# app/account/forms.py — No length or complexity validator on the password field
class The_Accounts(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired()])
    ...
    # password field does not appear in the WTForm — taken raw via request.form
```

**Fix:**  
Add a password field to the form with length and complexity validators, and require the user to enter the password twice for confirmation:
```python
from wtforms.validators import Length, EqualTo
password = PasswordField("Password", validators=[
    DataRequired(), Length(min=8),
    EqualTo("confirm", message="Passwords must match")
])
confirm = PasswordField("Confirm Password")
```

---

## V-06 — Stored Cross-Site Scripting (XSS) via CKEditor Post Body

| Field            | Detail |
|------------------|--------|
| **File**         | `app/dashboard/routes.py` — Lines 213–228 |
| **OWASP**        | A03:2021 – Injection |
| **CWE**          | CWE-79: Improper Neutralization of Input During Web Page Generation |
| **Severity**     | High |

**Description:**  
Blog post bodies are accepted from the CKEditor rich text editor and stored in the database without server-side sanitisation. The `body` field is rendered as raw HTML in post templates. An Author-role user can inject arbitrary JavaScript payloads that execute in the browser of every visitor who views that post, targeting both regular users and admins.

**Affected Code:**
```python
# app/dashboard/routes.py — Line 221
post = Blog_Posts(..., body=form.body.data, ...)
```

The original README acknowledges this risk:
> *"Giving authors the ability to edit the html opens many doors that bad actors could exploit."*

**Fix:**  
Sanitise the HTML on the server before storage using the `bleach` library, permitting only a safe allowlist of tags and attributes:
```python
import bleach
ALLOWED_TAGS = ['p', 'b', 'i', 'u', 'em', 'strong', 'a', 'ul', 'ol', 'li', 'br', 'h2', 'h3']
body_clean = bleach.clean(form.body.data, tags=ALLOWED_TAGS, strip=True)
```

---

## V-07 — Missing CSRF Protection on JSON API Endpoints

| Field            | Detail |
|------------------|--------|
| **File**         | `app/website/routes.py` — Lines 135, 163, 191, 218 |
| **OWASP**        | A01:2021 – Broken Access Control |
| **CWE**          | CWE-352: Cross-Site Request Forgery |
| **Severity**     | Medium |

**Description:**  
The comment, reply, like, and bookmark endpoints accept `POST` requests via `application/json` content type without any CSRF token validation. Flask-WTF's CSRF protection only covers form submissions. A malicious third-party website can craft JavaScript `fetch()` calls targeting these endpoints on behalf of an authenticated victim user, causing actions (likes, comments, deletions) to be performed without the user's knowledge.

**Affected Code:**
```python
# app/website/routes.py — Line 135
@website.route("/comment_post/<int:index>", methods=["POST"])
def post_comment(index):
    data = request.get_json()  # No CSRF token checked
```

**Fix:**  
Include CSRF token verification for JSON requests by passing the token in a custom request header (`X-CSRFToken`) and validating it server-side using `flask_wtf.csrf.validate_csrf`.

---

## V-08 — Unauthenticated Comment and Reply Deletion

| Field            | Detail |
|------------------|--------|
| **File**         | `app/website/routes.py` — Lines 163–188 |
| **OWASP**        | A01:2021 – Broken Access Control |
| **CWE**          | CWE-862: Missing Authorization |
| **Severity**     | High |

**Description:**  
The `/delete_comment_or_reply/<int:index>` endpoint carries no `@login_required` decorator and performs no ownership check. Any unauthenticated party — or any authenticated user — can send a POST request with a valid `commentId` or `replyId` and permanently delete content that belongs to another user, with no identity verification required.

**Affected Code:**
```python
# app/website/routes.py — Line 163
@website.route("/delete_comment_or_reply/<int:index>", methods=["POST"])
def post_delete_comment(index):
    # No @login_required
    # No ownership check
    res = delete_comment(int(data.get('commentId')))
```

**Fix:**  
Add `@login_required` and verify that the comment or reply being deleted belongs to `current_user.id` before invoking the delete helper.

---

## V-09 — No Email Format Validation at Signup

| Field            | Detail |
|------------------|--------|
| **File**         | `app/account/routes.py` — Line 36, `app/account/forms.py` |
| **OWASP**        | A07:2021 – Identification and Authentication Failures |
| **CWE**          | CWE-1286: Improper Validation of Syntactic Correctness of Input |
| **Severity**     | Low |

**Description:**  
The signup route accepts any string as the email address. The `The_Accounts` form applies `DataRequired()` but does not apply an `Email()` validator. Garbage strings such as `"notanemail"` or `"@"` are accepted and stored in the database. This bypasses any downstream logic that depends on the email field being a valid address (e.g., password recovery or admin email notifications).

**Affected Code:**
```python
# app/account/forms.py — Line 11
email = StringField("Email", validators=[DataRequired()])
# Missing: Email() validator from wtforms.validators
```

**Fix:**
```python
from wtforms.validators import DataRequired, Email
email = StringField("Email", validators=[DataRequired(), Email()])
```

---

## V-10 — No Session Timeout Configuration

| Field            | Detail |
|------------------|--------|
| **File**         | `app/config.py` |
| **OWASP**        | A07:2021 – Identification and Authentication Failures |
| **CWE**          | CWE-613: Insufficient Session Expiration |
| **Severity**     | Medium |

**Description:**  
No `PERMANENT_SESSION_LIFETIME` value is configured. Flask-Login sessions persist indefinitely by default until the browser is closed, and even beyond that if the browser restores sessions. On shared or public devices, an abandoned authenticated session remains valid with no server-enforced expiry.

**Note:** `from datetime import timedelta` is imported in `config.py` but never used, indicating this was recognised as a future task and left unimplemented.

**Fix:**
```python
from datetime import timedelta
PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
```
Additionally set `SESSION_COOKIE_SECURE = True`, `SESSION_COOKIE_HTTPONLY = True`, and `SESSION_COOKIE_SAMESITE = "Lax"` in the config.

---

## V-11 — Missing HTTP Security Headers

| Field            | Detail |
|------------------|--------|
| **File**         | `app/__init__.py`, `app/config.py` |
| **OWASP**        | A05:2021 – Security Misconfiguration |
| **CWE**          | CWE-693: Protection Mechanism Failure |
| **Severity**     | Medium |

**Description:**  
No HTTP security headers are set on responses. The following headers are absent:

| Header | Risk of Absence |
|--------|----------------|
| `Content-Security-Policy` | Allows XSS payloads to load external scripts |
| `X-Frame-Options` | Allows the application to be embedded in an iframe (clickjacking) |
| `X-Content-Type-Options` | Allows MIME-type sniffing attacks |
| `Referrer-Policy` | Leaks full URLs to external sites via the `Referer` header |
| `Strict-Transport-Security` | Allows downgrade to HTTP on HTTPS-deployed instances |

**Fix:**  
Use the `flask-talisman` extension to enforce security headers in a single configuration block, or add them manually via an `after_request` hook.

---

## V-12 — Client-Side File Size Validation Bypass on Image Upload

| Field            | Detail |
|------------------|--------|
| **File**         | `app/dashboard/routes.py` — Lines 264, 272, 280 |
| **OWASP**        | A03:2021 – Injection / A05:2021 – Security Misconfiguration |
| **CWE**          | CWE-434: Unrestricted Upload of File with Dangerous Type |
| **Severity**     | Medium |

**Description:**  
Blog post image size is validated using a value submitted in the form (`form.picture_v_size.data`), which is populated by client-side JavaScript. An attacker can bypass this check entirely by submitting a crafted POST request with a falsified size value (e.g., `"0"`), causing an oversized file to bypass the 1.5 MB guard and be saved to the server. Although `MAX_CONTENT_LENGTH` provides a hard server-side ceiling of 16 MB, the per-image 1.5 MB limit is not enforced server-side.

**Affected Code:**
```python
# app/dashboard/routes.py — Line 264
if form.picture_v.data and int(form.picture_v_size.data) < 1500000:
    # form.picture_v_size.data is client-supplied — trivially falsified
```

**Fix:**  
Measure the file size server-side using `len(form.picture_v.data.read())` and reject the upload before saving if it exceeds the threshold.

---

## V-13 — No Rate Limiting on Contact Form (Spam / Abuse)

| Field            | Detail |
|------------------|--------|
| **File**         | `app/website/routes.py` — Lines 81–98 |
| **OWASP**        | A05:2021 – Security Misconfiguration |
| **CWE**          | CWE-770: Allocation of Resources Without Limits or Throttling |
| **Severity**     | Low |

**Description:**  
The `/contact/` endpoint accepts POST requests from unauthenticated visitors with no rate limiting and no CAPTCHA. Each submission writes a record to the database and triggers an outbound email via SMTP. An automated script can flood the endpoint, exhausting the inbox of the admin, filling the `blog_contact` database table with junk records, and potentially triggering Gmail API rate limits that disable the application's email functionality entirely.

**Affected Code:**
```python
# app/website/routes.py — Lines 83–95
if request.method == "POST":
    ...
    db.session.add(new_contact)
    db.session.commit()
    send_email(contact_name, contact_email, contact_message)
    # No rate limit, no CAPTCHA, no authentication required
```

**Fix:**  
Apply `flask-limiter` with a per-IP limit (e.g., 5 requests per 10 minutes) and add a honeypot field or an integration with a CAPTCHA service such as hCaptcha.

---

## V-14 — ⚠️ ADDED — Verbose Exception Disclosure on Contact Form Error

> **Note:** This vulnerability was deliberately introduced into the codebase for the purposes of this assessment. The change is clearly annotated in the source code with a `[VULNERABILITY ADDED]` comment.

| Field            | Detail |
|------------------|--------|
| **File**         | `app/website/routes.py` — Lines 89–92 |
| **OWASP**        | A05:2021 – Security Misconfiguration |
| **CWE**          | CWE-209: Generation of Error Message Containing Sensitive Information |
| **Severity**     | Medium |
| **Status**       | **Introduced by assessor** |

**Description:**  
The `except` block in the contact form submission handler was modified to catch the exception object and return its string representation directly in the HTTP response body. If a database error occurs (e.g., a schema mismatch, a constraint violation, or a misconfigured connection), the full SQLAlchemy exception message — which can include the SQL statement, table names, column names, and internal file paths — is returned to the client in plain text.

This constitutes an **Information Disclosure** vulnerability. An attacker can deliberately trigger this error (e.g., by sending a payload that violates a database constraint) and use the leaked schema details to craft more targeted injection or enumeration attacks.

**Introduced Code:**
```python
# app/website/routes.py — Lines 89–92
except Exception as e:
    # [VULNERABILITY ADDED]: Exposes full internal exception details to the client.
    # CWE-209: Generation of Error Message Containing Sensitive Information.
    return f"There was an error adding message to the database: {str(e)}"
```

**Original (Safe) Code:**
```python
except:
    return "There was an error adding message to the database."
```

**Fix:**  
Revert to the original generic error message. Log the exception server-side using Python's `logging` module, and never expose exception objects or stack traces in HTTP responses.

---

## Summary Table

| ID    | Vulnerability                              | OWASP Category                                | Severity | Status        |
|-------|--------------------------------------------|-----------------------------------------------|----------|---------------|
| V-01  | Hardcoded Secret Key                       | A05 – Security Misconfiguration               | Critical | Original code |
| V-02  | IDOR on Account Update                     | A01 – Broken Access Control                   | High     | Original code |
| V-03  | Missing Role Auth on Admin Routes          | A01 – Broken Access Control                   | High     | Original code |
| V-04  | No Brute Force Protection on Login         | A07 – Auth Failures                           | High     | Original code |
| V-05  | No Password Complexity Enforcement         | A07 – Auth Failures                           | Medium   | Original code |
| V-06  | Stored XSS via CKEditor                    | A03 – Injection                               | High     | Original code |
| V-07  | Missing CSRF on JSON API Endpoints         | A01 – Broken Access Control                   | Medium   | Original code |
| V-08  | Unauthenticated Comment/Reply Deletion     | A01 – Broken Access Control                   | High     | Original code |
| V-09  | No Email Format Validation at Signup       | A07 – Auth Failures                           | Low      | Original code |
| V-10  | No Session Timeout                         | A07 – Auth Failures                           | Medium   | Original code |
| V-11  | Missing HTTP Security Headers              | A05 – Security Misconfiguration               | Medium   | Original code |
| V-12  | Client-Side File Size Validation Bypass    | A05 – Security Misconfiguration               | Medium   | Original code |
| V-13  | No Rate Limiting on Contact Form           | A05 – Security Misconfiguration               | Low      | Original code |
| V-14  | ⚠️ Verbose Exception Disclosure (ADDED)   | A05 – Security Misconfiguration               | Medium   | **Introduced** |
