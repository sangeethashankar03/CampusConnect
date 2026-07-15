from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

from app.extensions import db
from app.models.group import Group, GroupMembership
from app.groups.permissions import group_member_required

groups_bp = Blueprint("groups", __name__)


@groups_bp.route("/", methods=["POST"])
@jwt_required()
def create_group():
    data = request.get_json(silent=True) or {}
    name = data.get("name", "").strip()
    module_code = data.get("module_code", "").strip()
    if not name:
        return jsonify({"error": "Group name is required"}), 400

    user_id = int(get_jwt_identity())
    group = Group(name=name, module_code=module_code, created_by=user_id)
    db.session.add(group)
    db.session.flush()

    db.session.add(GroupMembership(group_id=group.id, user_id=user_id, role="owner"))
    db.session.commit()
    return jsonify({"id": group.id, "name": group.name}), 201


@groups_bp.route("/<int:group_id>/join", methods=["POST"])
@jwt_required()
def join_group(group_id):
    user_id = int(get_jwt_identity())
    existing = GroupMembership.query.filter_by(group_id=group_id, user_id=user_id).first()
    if existing:
        return jsonify({"error": "Already a member"}), 409
    db.session.add(GroupMembership(group_id=group_id, user_id=user_id, role="member"))
    db.session.commit()
    return jsonify({"message": "Joined group"}), 200

@groups_bp.route("/<int:group_id>/leave", methods=["POST"])
@jwt_required()
@group_member_required
def leave_group(group_id):
    user_id = int(get_jwt_identity())
    membership = GroupMembership.query.filter_by(group_id=group_id, user_id=user_id).first()
    db.session.delete(membership)
    db.session.commit()
    return jsonify({"message": "Left group"}), 200


@groups_bp.route("/<int:group_id>/members", methods=["GET"])
@jwt_required()
@group_member_required
def list_members(group_id):
    members = GroupMembership.query.filter_by(group_id=group_id).all()
    return jsonify([{"user_id": m.user_id, "role": m.role} for m in members]), 200