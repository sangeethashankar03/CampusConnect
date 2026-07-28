import base64
import json

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

from app.extensions import db
from app.models.file import SharedFile, FileKey
from app.models.group import GroupMembership
from app.groups.permissions import group_member_required
from app.files.storage import save_ciphertext_blob, load_ciphertext_blob

files_bp = Blueprint("files", __name__)


@files_bp.route("/<int:group_id>/upload", methods=["POST"])
@jwt_required()
@group_member_required
def upload_file(group_id):
    """
    Envelope-encrypted upload. The client has already: generated a one-off
    AES-256-GCM key and encrypted the file with it; fetched every current
    group member's RSA public key (GET /groups/<id>/members); wrapped
    (RSA-OAEP encrypted) that same AES key once per member. This endpoint
    receives the ciphertext (as a file part), the nonce, and a JSON array
    of {user_id, wrapped_key} -- it never generates a key and never sees
    plaintext, unlike the previous version of this endpoint.
    """
    if "file" not in request.files:
        return jsonify({"error": "No file part in request"}), 400
    if "nonce" not in request.form or "wrapped_keys" not in request.form:
        return jsonify({"error": "nonce and wrapped_keys are required"}), 400

    try:
        wrapped_keys = json.loads(request.form["wrapped_keys"])
    except ValueError:
        return jsonify({"error": "wrapped_keys must be JSON"}), 400
    if not isinstance(wrapped_keys, list) or not wrapped_keys:
        return jsonify({"error": "wrapped_keys must be a non-empty list"}), 400

    upload = request.files["file"]
    ciphertext_bytes = upload.read()
    stored_filename = save_ciphertext_blob(ciphertext_bytes)

    record = SharedFile(
        group_id=group_id,
        uploader_id=int(get_jwt_identity()),
        original_filename=upload.filename,
        stored_filename=stored_filename,
        nonce=request.form["nonce"],
    )
    db.session.add(record)
    db.session.flush()

    # Only wrap keys for people who are actually in the group -- otherwise a
    # malicious client could plant a wrapped key for an outsider's public key.
    member_ids = {m.user_id for m in GroupMembership.query.filter_by(group_id=group_id).all()}
    for entry in wrapped_keys:
        uid = entry.get("user_id")
        wrapped = entry.get("wrapped_key")
        if uid not in member_ids or not wrapped:
            continue
        db.session.add(FileKey(file_id=record.id, user_id=uid, wrapped_key=wrapped))
    db.session.commit()
    return jsonify({"id": record.id, "filename": record.original_filename}), 201


@files_bp.route("/<int:group_id>/<int:file_id>/download", methods=["GET"])
@jwt_required()
@group_member_required
def download_file(group_id, file_id):
    record = SharedFile.query.filter_by(id=file_id, group_id=group_id).first()
    if not record:
        return jsonify({"error": "File not found"}), 404

    my_key = FileKey.query.filter_by(file_id=file_id, user_id=int(get_jwt_identity())).first()
    if not my_key:
        # e.g. they joined after this file was uploaded -- there's genuinely
        # no wrapped key for them, so they cannot decrypt it. Correct
        # behaviour, not a bug.
        return jsonify({"error": "No decryption key available for you on this file (joined after upload?)"}), 403

    ciphertext_bytes = load_ciphertext_blob(record.stored_filename)
    return jsonify({
        "ciphertext": base64.b64encode(ciphertext_bytes).decode(),
        "nonce": record.nonce,
        "wrapped_key": my_key.wrapped_key,
        "original_filename": record.original_filename,
    }), 200


@files_bp.route("/<int:group_id>", methods=["GET"])
@jwt_required()
@group_member_required
def list_files(group_id):
    files = SharedFile.query.filter_by(group_id=group_id).all()
    return jsonify([
        {"id": f.id, "original_filename": f.original_filename, "uploaded_at": f.uploaded_at.isoformat(),
         "uploader_id": f.uploader_id}
        for f in files
    ]), 200