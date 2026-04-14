from flask import Flask
import app.extensions as extensions
from app.config import Config
import os

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    extensions.db.init_app(app)
    extensions.ckeditor.init_app(app)
    extensions.login_manager.init_app(app)

    # V-07 FIX: Initialize global CSRF protection (covers all WTForms POST requests).
    extensions.csrf.init_app(app)

    # V-04 / V-13 FIX: Initialize rate limiter.
    extensions.limiter.init_app(app)

    from app.account.routes import account
    from app.dashboard.routes import dashboard
    from app.website.routes import website
    from app.error_handlers.routes import error_handler
    from flask import current_app

    from app.models import user, posts, themes, contact, bookmarks, comments, stats

    app.register_blueprint(account)
    app.register_blueprint(dashboard)
    app.register_blueprint(website)
    app.register_blueprint(error_handler)

    # V-11 FIX: Inject HTTP security headers on every response.
    @app.after_request
    def set_security_headers(response):
        # Prevent MIME-type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"
        # Prevent clickjacking via iframes
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        # Control referrer information sent to external sites
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        # Content Security Policy: restrict resource origins.
        # cdn.ckeditor.com is explicitly allowed for scripts, styles, images and
        # frames because CKEditor 4 loads its toolbar, skins and plugins from that CDN.
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://code.jquery.com https://cdnjs.cloudflare.com https://cdn.ckeditor.com; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com https://cdn.ckeditor.com; "
            "font-src 'self' https://fonts.gstatic.com https://cdn.ckeditor.com; "
            "img-src 'self' data: https://cdn.ckeditor.com; "
            "frame-src 'self'; "
            "connect-src 'self' https://cdn.ckeditor.com;"
        )
        return response

    @app.route('/test/')
    def test_page():
        return '<h1> Testing the App </h1>'

    ABS_PATH = os.path.dirname(__file__)
    REL_PATH = "static"

    STATIC_PATH = repr(str(app.config["STATIC_FOLDER"]))

    @app.route("/../static/<filename>")
    def static_path():
        pass

    return app
