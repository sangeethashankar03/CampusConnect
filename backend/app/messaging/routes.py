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
        signature=data["signature"],
    )
    db.session.add(message)
    db.session.commit()
    return jsonify(message.to_dict()), 201