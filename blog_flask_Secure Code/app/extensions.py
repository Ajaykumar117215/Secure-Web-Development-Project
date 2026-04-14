from flask_sqlalchemy import SQLAlchemy
from flask_ckeditor import CKEditor
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

db = SQLAlchemy()
ckeditor = CKEditor()
login_manager = LoginManager()

# V-07 / V-13 FIX: Global CSRF protection for all form-based POST routes.
# JSON API routes are individually exempted and validated via X-CSRFToken header.
csrf = CSRFProtect()

# V-04 / V-13 FIX: Rate limiter keyed by remote IP address.
limiter = Limiter(key_func=get_remote_address, default_limits=[])
