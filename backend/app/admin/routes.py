from flask import Blueprint, jsonify

from app.auth.decorators import role_required
from app.models.user import User

admin_bp = Blueprint("admin", __name__)


@admin_bp.route("/users", methods=["GET"])
@role_required("admin")
def list_all_users():
    """
    Demonstrates role_required actually gating something: only accounts
    with role='admin' can see the full user roster. Promote a user with:
        UPDATE users SET role = 'admin' WHERE email = '...';
    """
    users = User.query.order_by(User.created_at.desc()).all()
    return jsonify([
        {**u.to_dict(), "created_at": u.created_at.isoformat()} for u in users
    ]), 200