from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

from app.extensions import db
from app.models.key import PublicKey

crypto_bp = Blueprint("crypto", __name__)


@crypto_bp.route("/register", methods=["POST"])
@jwt_required()
def register_public_key():
    """
    The client generates both RSA key pairs in the browser and keeps the
    private keys. It posts only the two public keys (PEM) here.
    """
    data = request.get_json(silent=True) or {}
    encryption_key_pem = data.get("encryption_key")
    signing_key_pem = data.get("signing_key")

    if not encryption_key_pem or not signing_key_pem:
        return jsonify({"error": "encryption_key and signing_key are both required"}), 400

    user_id = int(get_jwt_identity())
    existing = PublicKey.query.filter_by(user_id=user_id).first()
    if existing:
        existing.encryption_key_pem = encryption_key_pem
        existing.signing_key_pem = signing_key_pem
    else:
        db.session.add(
            PublicKey(
                user_id=user_id,
                encryption_key_pem=encryption_key_pem,
                signing_key_pem=signing_key_pem,
            )
        )
    db.session.commit()
    return jsonify({"message": "Public keys registered"}), 201
@crypto_bp.route("/<int:user_id>", methods=["GET"])
@jwt_required()
def get_public_key(user_id):
    key = PublicKey.query.filter_by(user_id=user_id).first()
    if not key:
        return jsonify({"error": "No public key found for this user"}), 404
    return jsonify(
        {
            "user_id": user_id,
            "encryption_key": key.encryption_key_pem,
            "signing_key": key.signing_key_pem,
        }
    ), 200