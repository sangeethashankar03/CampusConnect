from datetime import datetime
from app.extensions import db


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="student", nullable=False)

    is_verified = db.Column(db.Boolean, default=True, nullable=False)

    # --- Brute-force login protection ---
    failed_login_count = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime, nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    public_key = db.relationship(
        "PublicKey", backref="owner", uselist=False, cascade="all, delete-orphan"
    )

    def to_dict(self):
        return {
            "id": self.id,
            "email": self.email,
            "username": self.username,
            "role": self.role,
            "is_verified": self.is_verified,
        }


class PendingVerification(db.Model):
    """
    Holds an email + one-time code BEFORE any User account exists. A row
    here means "someone claims this email and we sent them a code" -- it
    is deleted once registration completes, or replaced if they request a
    new code. No password is stored here; that only happens once the code
    is confirmed correct, in the final registration step.
    """
    __tablename__ = "pending_verifications"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    code = db.Column(db.String(6), nullable=False)
    is_verified = db.Column(db.Boolean, default=False, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)