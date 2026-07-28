import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-me")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", "postgresql://campusconnect:password@localhost:5432/campusconnect"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "dev-jwt-secret-change-me")
    JWT_ACCESS_TOKEN_EXPIRES = 3600
    MAX_CONTENT_LENGTH = 15 * 1024 * 1024
    UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", "uploads")

    LOGIN_MAX_ATTEMPTS = 5
    LOGIN_LOCKOUT_SECONDS = 300

    # Gmail SMTP settings for real email verification codes.
    # MAIL_PASSWORD must be a 16-character Gmail "app password", NOT your
    # real Gmail password -- Google blocks plain-password SMTP entirely.
    MAIL_SERVER = "smtp.gmail.com"
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get("MAIL_USERNAME", "")
    MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD", "")
    VERIFICATION_CODE_EXPIRY_SECONDS = 600  # 10 minutes


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    JWT_SECRET_KEY = "test-secret"