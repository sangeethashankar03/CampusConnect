from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity

from app.extensions import db, bcrypt
from app.models.user import User
from app.auth.validators import is_valid_email, is_valid_password, is_valid_username

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    email = data.get("email", "").strip().lower()
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not is_valid_email(email):
        return jsonify({"error": "Invalid email format"}), 400
    if not is_valid_username(username):
        return jsonify({"error": "Username must be 3-80 characters"}), 400
    if not is_valid_password(password):
        return jsonify({"error": "Password must be 8+ characters with a letter and a digit"}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email already registered"}), 409
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username already taken"}), 409

    password_hash = bcrypt.generate_password_hash(password).decode("utf-8")
    user = User(email=email, username=username, password_hash=password_hash)
    db.session.add(user)
    db.session.commit()

    return jsonify({"message": "Registered successfully", "user": user.to_dict()}), 201


@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    user = User.query.filter_by(email=email).first()
    if not user or not bcrypt.check_password_hash(user.password_hash, password):
        return jsonify({"error": "Invalid email or password"}), 401

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
    results = User.query.filter(User.username.ilike(f"%{q}%")).limit(10).all()
    return jsonify([u.to_dict() for u in results]), 200