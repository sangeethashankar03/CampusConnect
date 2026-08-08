from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
import re
from app.extensions import db
from app.models.group import Group, GroupMembership, GroupInvite
from app.models.message import GroupMessage, GroupMessageKey
from app.models.user import User
from app.groups.permissions import group_member_required, group_owner_required

groups_bp = Blueprint("groups", __name__)


@groups_bp.route("/", methods=["GET"])
@jwt_required()
def list_my_groups():
    user_id = int(get_jwt_identity())
    memberships = GroupMembership.query.filter_by(user_id=user_id).all()
    results = []
    for m in memberships:
        g = Group.query.get(m.group_id)
        results.append({"id": g.id, "name": g.name, "module_code": g.module_code, "role": m.role})
    return jsonify(results), 200


@groups_bp.route("/", methods=["POST"])
@jwt_required()
def create_group():
    data = request.get_json(silent=True) or {}
    name = data.get("name", "").strip()
    name = re.sub(r'<[^>]+>', '', name)
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


@groups_bp.route("/<int:group_id>/invite", methods=["POST"])
@jwt_required()
@group_owner_required
def invite_member(group_id):
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    if not username:
        return jsonify({"error": "username is required"}), 400

    target = User.query.filter_by(username=username).first()
    if not target:
        return jsonify({"error": "No such user"}), 404

    if GroupMembership.query.filter_by(group_id=group_id, user_id=target.id).first():
        return jsonify({"error": f"{username} is already a member"}), 409

    existing_invite = GroupInvite.query.filter_by(group_id=group_id, invited_user_id=target.id).first()
    if existing_invite and existing_invite.status == "pending":
        return jsonify({"error": f"{username} already has a pending invite"}), 409

    if existing_invite:
        existing_invite.status = "pending"
        existing_invite.invited_by = int(get_jwt_identity())
    else:
        db.session.add(GroupInvite(group_id=group_id, invited_user_id=target.id, invited_by=int(get_jwt_identity())))
    db.session.commit()
    return jsonify({"message": f"Invited {username}"}), 201


@groups_bp.route("/invites/pending", methods=["GET"])
@jwt_required()
def list_pending_invites():
    user_id = int(get_jwt_identity())
    invites = GroupInvite.query.filter_by(invited_user_id=user_id, status="pending").all()
    results = []
    for inv in invites:
        group = Group.query.get(inv.group_id)
        inviter = User.query.get(inv.invited_by)
        results.append({
            "invite_id": inv.id, "group_id": group.id, "group_name": group.name,
            "invited_by_username": inviter.username,
        })
    return jsonify(results), 200


@groups_bp.route("/invites/<int:invite_id>/accept", methods=["POST"])
@jwt_required()
def accept_invite(invite_id):
    invite = GroupInvite.query.get(invite_id)
    if not invite or invite.invited_user_id != int(get_jwt_identity()):
        return jsonify({"error": "Invite not found"}), 404
    if invite.status != "pending":
        return jsonify({"error": f"Invite already {invite.status}"}), 409

    invite.status = "accepted"
    if not GroupMembership.query.filter_by(group_id=invite.group_id, user_id=invite.invited_user_id).first():
        db.session.add(GroupMembership(group_id=invite.group_id, user_id=invite.invited_user_id, role="member"))
    db.session.commit()
    return jsonify({"message": "Joined group", "group_id": invite.group_id}), 200


@groups_bp.route("/invites/<int:invite_id>/reject", methods=["POST"])
@jwt_required()
def reject_invite(invite_id):
    invite = GroupInvite.query.get(invite_id)
    if not invite or invite.invited_user_id != int(get_jwt_identity()):
        return jsonify({"error": "Invite not found"}), 404
    invite.status = "rejected"
    db.session.commit()
    return jsonify({"message": "Invite declined"}), 200


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
    """Includes each member's public encryption + signing key PEMs, needed
    for the client to do envelope encryption (files) and signature
    verification (group chat) without extra round trips."""
    memberships = GroupMembership.query.filter_by(group_id=group_id).all()
    results = []
    for m in memberships:
        user = User.query.get(m.user_id)
        pk = user.public_key
        results.append({
            "user_id": user.id, "username": user.username, "role": m.role,
            "encryption_key": pk.encryption_key_pem if pk else None,
            "signing_key": pk.signing_key_pem if pk else None,
        })
    return jsonify(results), 200


@groups_bp.route("/<int:group_id>/messages", methods=["POST"])
@jwt_required()
@group_member_required
def send_group_message(group_id):
    data = request.get_json(silent=True) or {}
    required = ["ciphertext", "nonce", "signature", "wrapped_keys"]
    if not all(data.get(f) for f in required):
        return jsonify({"error": f"Missing fields, need: {', '.join(required)}"}), 400
    if not isinstance(data["wrapped_keys"], list) or not data["wrapped_keys"]:
        return jsonify({"error": "wrapped_keys must be a non-empty list"}), 400

    user_id = int(get_jwt_identity())
    message = GroupMessage(
        group_id=group_id, sender_id=user_id,
        ciphertext=data["ciphertext"], nonce=data["nonce"], signature=data["signature"],
    )
    db.session.add(message)
    db.session.flush()

    member_ids = {m.user_id for m in GroupMembership.query.filter_by(group_id=group_id).all()}
    for entry in data["wrapped_keys"]:
        uid = entry.get("user_id")
        wrapped = entry.get("wrapped_key")
        if uid not in member_ids or not wrapped:
            continue
        db.session.add(GroupMessageKey(group_message_id=message.id, user_id=uid, wrapped_key=wrapped))
    db.session.commit()

    return jsonify({
        "id": message.id, "group_id": group_id, "sender_id": user_id,
        "ciphertext": message.ciphertext, "nonce": message.nonce, "signature": message.signature,
        "created_at": message.created_at.isoformat(),
    }), 201


@groups_bp.route("/<int:group_id>/messages", methods=["GET"])
@jwt_required()
@group_member_required
def get_group_messages(group_id):
    user_id = int(get_jwt_identity())
    messages = GroupMessage.query.filter_by(group_id=group_id).order_by(GroupMessage.created_at.asc()).all()
    results = []
    for m in messages:
        sender = User.query.get(m.sender_id)
        my_key = GroupMessageKey.query.filter_by(group_message_id=m.id, user_id=user_id).first()
        results.append({
            "id": m.id, "sender_id": m.sender_id, "sender_username": sender.username,
            "ciphertext": m.ciphertext, "nonce": m.nonce, "signature": m.signature,
            "created_at": m.created_at.isoformat(),
            "wrapped_key": my_key.wrapped_key if my_key else None,
        })
    return jsonify(results), 200