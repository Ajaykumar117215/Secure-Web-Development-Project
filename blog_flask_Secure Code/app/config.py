import os
from dotenv import load_dotenv  # getting .env variables
from datetime import timedelta

load_dotenv()

class Config:
    # V-01 FIX: Load SECRET_KEY from environment variable — never hardcode it.
    # Add SECRET_KEY=<random-string> to your .env file before running.
    SECRET_KEY = os.getenv("SECRET_KEY")
    if not SECRET_KEY:
        raise RuntimeError(
            "SECRET_KEY environment variable is not set. "
            "Add SECRET_KEY=<random-string> to your .env file."
        )

    SQLALCHEMY_DATABASE_URI = 'sqlite:///admin.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    TEMPLATES_AUTO_RELOAD = True
    ABSOLUTE_PATH = os.path.dirname(__file__)
    RELATIVE_PATH = "static/Pictures_Users"
    BLOG_PICTURES_PATH = "static/Pictures_Posts"
    PROFILE_IMG_FOLDER = os.path.join(ABSOLUTE_PATH, RELATIVE_PATH)
    BLOG_IMG_FOLDER = os.path.join(ABSOLUTE_PATH, BLOG_PICTURES_PATH)
    STATIC_FOLDER = os.path.join(ABSOLUTE_PATH, "static")
    ALLOWED_IMG_EXTENSIONS = ['PNG', 'JPG', 'JPEG']
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024

    # V-10 FIX: Session timeout and secure cookie flags.
    # Sessions expire after 30 minutes of inactivity.
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    SESSION_COOKIE_HTTPONLY = True   # Prevent JS access to the session cookie
    SESSION_COOKIE_SAMESITE = "Lax"  # Mitigate CSRF via cross-site requests
    # SESSION_COOKIE_SECURE = True   # Enable this in production (HTTPS only)

