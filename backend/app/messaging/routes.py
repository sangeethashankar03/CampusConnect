from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

from app.extensions import db
from app.models.message import Message
from app.messaging.services import validate_encrypted_payload

messaging_bp = Blueprint("messaging", __name__)


@messaging_bp.route("/", methods=["POST"])
@jwt_required()
def send_message():
    data = request.get_json(silent=True) or {}
    ok, error = validate_encrypted_payload(data)
    if not ok:
        return jsonify({"error": error}), 400

    message = Message(
        sender_id=int(get_jwt_identity()),
        receiver_id=data["receiver_id"],
        ciphertext=data["ciphertext"],
        nonce=data["nonce"],
        enc_aes_key=data["enc_aes_key"],
        enc_aes_key_sender=data.get("enc_aes_key_sender"),
        signature=data["signature"],
        is_file=data.get("is_file", False),
        original_filename=data.get("original_filename"),
    )
    db.session.add(message)
    db.session.commit()
    return jsonify(message.to_dict()), 201


@messaging_bp.route("/<int:peer_id>", methods=["GET"])
@jwt_required()
def get_conversation(peer_id):
    user_id = int(get_jwt_identity())
    messages = (
        Message.query.filter(
            ((Message.sender_id == user_id) & (Message.receiver_id == peer_id))
            | ((Message.sender_id == peer_id) & (Message.receiver_id == user_id))
        )
        .order_by(Message.created_at.asc())
        .all()
    )
    return jsonify([m.to_dict() for m in messages]), 200

from app.models.conversations import Conversation


@messaging_bp.route("/conversations/request", methods=["POST"])
@jwt_required()
def request_conversation():
    data = request.get_json(silent=True) or {}
    peer_id = data.get("peer_id")
    if not peer_id:
        return jsonify({"error": "peer_id is required"}), 400

    user_id = int(get_jwt_identity())
    existing = Conversation.query.filter(
        ((Conversation.creator_id == user_id) & (Conversation.joiner_id == peer_id))
        | ((Conversation.creator_id == peer_id) & (Conversation.joiner_id == user_id))
    ).first()
    if existing:
        return jsonify({"error": "A request already exists with this user", "status": existing.status}), 409

    conversation = Conversation(creator_id=user_id, joiner_id=peer_id, status="pending")
    db.session.add(conversation)
    db.session.commit()
    return jsonify({"conversation_id": conversation.id, "status": "pending"}), 201


@messaging_bp.route("/conversations/pending", methods=["GET"])
@jwt_required()
def list_pending_requests():
    from app.models.user import User
    user_id = int(get_jwt_identity())
    pending = Conversation.query.filter_by(joiner_id=user_id, status="pending").all()
    results = []
    for conv in pending:
        creator = User.query.get(conv.creator_id)
        results.append({"conversation_id": conv.id, "from_username": creator.username, "from_id": creator.id})
    return jsonify(results), 200


@messaging_bp.route("/conversations/sent", methods=["GET"])
@jwt_required()
def list_sent_requests():
    from app.models.user import User
    user_id = int(get_jwt_identity())
    sent = Conversation.query.filter_by(creator_id=user_id).all()
    results = []
    for conv in sent:
        joiner = User.query.get(conv.joiner_id)
        results.append({"conversation_id": conv.id, "to_username": joiner.username, "status": conv.status})
    return jsonify(results), 200


@messaging_bp.route("/conversations/<int:conversation_id>/accept", methods=["POST"])
@jwt_required()
def accept_conversation(conversation_id):
    conversation = Conversation.query.get(conversation_id)
    if not conversation or conversation.joiner_id != int(get_jwt_identity()):
        return jsonify({"error": "Request not found"}), 404
    conversation.status = "accepted"
    db.session.commit()
    return jsonify({"status": "accepted", "peer_id": conversation.creator_id}), 200


@messaging_bp.route("/conversations/<int:conversation_id>/reject", methods=["POST"])
@jwt_required()
def reject_conversation(conversation_id):
    conversation = Conversation.query.get(conversation_id)
    if not conversation or conversation.joiner_id != int(get_jwt_identity()):
        return jsonify({"error": "Request not found"}), 404
    conversation.status = "rejected"
    db.session.commit()
    return jsonify({"status": "rejected"}), 200