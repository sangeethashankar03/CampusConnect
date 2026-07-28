import random
import re
from datetime import datetime, timedelta

from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity

from app.extensions import db, bcrypt
from app.models.user import User, PendingVerification
from app.auth.validators import is_valid_email, is_valid_password
from app.auth.mailer import send_verification_email

auth_bp = Blueprint("auth", __name__)


def _generate_username(email: str) -> str:
    """Auto-derives a username from the email prefix (e.g. sangeethagowda145
    -> sangeethagowda145), appending a number if that username is taken."""
    base = re.sub(r"[^A-Za-z0-9_.-]", "", email.split("@")[0]) or "user"
    username = base
    counter = 1
    while User.query.filter_by(username=username).first():
        counter += 1
        username = f"{base}{counter}"
    return username


@auth_bp.route("/request-code", methods=["POST"])
def request_code():
    """Step 1: user submits their Gmail address. We generate a 6-digit code,
    store it (replacing any previous one for this email), and send it via
    real Gmail SMTP."""
    data = request.get_json(silent=True) or {}
    email = data.get("email", "").strip().lower()

    if not is_valid_email(email):
        return jsonify({"error": "Please use a Google (gmail.com) email address"}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "An account with this email already exists"}), 409

    code = f"{random.randint(0, 999999):06d}"
    expires_at = datetime.utcnow() + timedelta(seconds=current_app.config["VERIFICATION_CODE_EXPIRY_SECONDS"])

    pending = PendingVerification.query.filter_by(email=email).first()
    if pending:
        pending.code = code
        pending.is_verified = False
        pending.expires_at = expires_at
    else:
        pending = PendingVerification(email=email, code=code, expires_at=expires_at)
        db.session.add(pending)
    db.session.commit()

    try:
        send_verification_email(email, code)
    except Exception as e:
        return jsonify({"error": f"Could not send verification email: {e}"}), 500

    return jsonify({"message": f"Verification code sent to {email}"}), 200


@auth_bp.route("/verify-code", methods=["POST"])
def verify_code():
    """Step 2: user submits the 6-digit code they received by email."""
    data = request.get_json(silent=True) or {}
    email = data.get("email", "").strip().lower()
    code = data.get("code", "").strip()

    pending = PendingVerification.query.filter_by(email=email).first()
    if not pending or pending.code != code:
        return jsonify({"error": "Invalid verification code"}), 400
    if pending.expires_at < datetime.utcnow():
        return jsonify({"error": "This code has expired -- request a new one"}), 400

    pending.is_verified = True
    db.session.commit()
    return jsonify({"message": "Email verified"}), 200


@auth_bp.route("/complete-registration", methods=["POST"])
def complete_registration():
    """Step 3: only reachable once verify_code succeeded for this email.
    User sets a password; username is auto-derived from their email, and
    the account is created already verified (they proved the inbox)."""
    data = request.get_json(silent=True) or {}
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    pending = PendingVerification.query.filter_by(email=email, is_verified=True).first()
    if not pending:
        return jsonify({"error": "Please verify your email first"}), 403
    if not is_valid_password(password):
        return jsonify({"error": "Password must be 10+ characters with upper, lower, digit and symbol"}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "An account with this email already exists"}), 409

    username = _generate_username(email)
    password_hash = bcrypt.generate_password_hash(password).decode("utf-8")
    user = User(email=email, username=username, password_hash=password_hash, is_verified=True)
    db.session.add(user)
    db.session.delete(pending)
    db.session.commit()

    return jsonify({"message": "Account created", "user": user.to_dict()}), 201


@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    user = User.query.filter_by(email=email).first()

    if user and user.locked_until and user.locked_until > datetime.utcnow():
        return jsonify({"error": "Too many failed attempts. Try again later."}), 429

    valid = user and bcrypt.check_password_hash(user.password_hash, password)
    if not valid:
        if user:
            user.failed_login_count += 1
            if user.failed_login_count >= current_app.config["LOGIN_MAX_ATTEMPTS"]:
                user.locked_until = datetime.utcnow() + timedelta(seconds=current_app.config["LOGIN_LOCKOUT_SECONDS"])
            db.session.commit()
        return jsonify({"error": "Invalid email or password"}), 401

    user.failed_login_count = 0
    user.locked_until = None
    db.session.commit()

    token = create_access_token(identity=str(user.id))
    return jsonify({"access_token": token, "user": user.to_dict()}), 200


@auth_bp.route("/me", methods=["GET"])
@jwt_required()
def me():
    user = User.query.get(int(get_jwt_identity()))
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify(user.to_dict()), 200


@auth_bp.route("/search", methods=["GET"])
@jwt_required()
def search_users():
    q = request.args.get("q", "").strip()
    if not q:
        return jsonify([]), 200
    results = User.query.filter(
        User.username.ilike(f"%{q}%"),
        User.id != int(get_jwt_identity()),
    ).limit(10).all()
    return jsonify([u.to_dict() for u in results]), 200