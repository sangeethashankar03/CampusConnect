from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

from app.extensions import db
from app.models.key import PublicKey

crypto_bp = Blueprint("crypto", __name__)


@crypto_bp.route("/register", methods=["POST"])
@jwt_required()
def register_keys():
    """
    Called once per account (first login after verification). The client
    generates both RSA keypairs in-browser, derives a key-encryption-key
    from the user's password (PBKDF2), and encrypts the private keys with
    it (AES-GCM) before this call -- only the two PUBLIC keys and the two
    ENCRYPTED private key blobs (+ the salt to re-derive the KEK) ever
    reach the server.
    """
    data = request.get_json(silent=True) or {}
    required = ["encryption_key", "signing_key", "enc_private_key_blob", "sign_private_key_blob", "kdf_salt"]
    if not all(data.get(f) for f in required):
        return jsonify({"error": f"Missing fields, need: {', '.join(required)}"}), 400

    user_id = int(get_jwt_identity())
    existing = PublicKey.query.filter_by(user_id=user_id).first()
    if existing:
        existing.encryption_key_pem = data["encryption_key"]
        existing.signing_key_pem = data["signing_key"]
        existing.enc_private_key_blob = data["enc_private_key_blob"]
        existing.sign_private_key_blob = data["sign_private_key_blob"]
        existing.kdf_salt = data["kdf_salt"]
    else:
        db.session.add(PublicKey(
            user_id=user_id,
            encryption_key_pem=data["encryption_key"],
            signing_key_pem=data["signing_key"],
            enc_private_key_blob=data["enc_private_key_blob"],
            sign_private_key_blob=data["sign_private_key_blob"],
            kdf_salt=data["kdf_salt"],
        ))
    db.session.commit()
    return jsonify({"message": "Keys registered"}), 201


@crypto_bp.route("/backup", methods=["GET"])
@jwt_required()
def get_my_backup():
    """
    Added: lets the SAME user, on a later login or a different device,
    fetch their own encrypted private key blobs + salt, re-derive the KEK
    from their password, and decrypt locally. This replaces the old
    behaviour of generating a brand new keypair on every login, which
    silently broke decryption of any message sent before that point.
    """
    key = PublicKey.query.filter_by(user_id=int(get_jwt_identity())).first()
    if not key:
        return jsonify({"error": "No key backup found for this account yet"}), 404
    return jsonify({
        "enc_private_key_blob": key.enc_private_key_blob,
        "sign_private_key_blob": key.sign_private_key_blob,
        "kdf_salt": key.kdf_salt,
    }), 200


@crypto_bp.route("/<int:user_id>", methods=["GET"])
@jwt_required()
def get_public_key(user_id):
    key = PublicKey.query.filter_by(user_id=user_id).first()
    if not key:
        return jsonify({"error": "No public key found for this user"}), 404
    return jsonify({
        "user_id": user_id,
        "encryption_key": key.encryption_key_pem,
        "signing_key": key.signing_key_pem,
    }), 200