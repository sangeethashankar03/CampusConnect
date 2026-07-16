import base64

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

from app.extensions import db
from app.models.file import SharedFile
from app.groups.permissions import group_member_required
from app.files.storage import save_encrypted_file

files_bp = Blueprint("files", __name__)


@files_bp.route("/<int:group_id>/upload", methods=["POST"])
@jwt_required()
@group_member_required
def upload_file(group_id):
    if "file" not in request.files:
        return jsonify({"error": "No file part in request"}), 400

    upload = request.files["file"]
    file_bytes = upload.read()

    stored_filename, aes_key, nonce = save_encrypted_file(file_bytes)

    record = SharedFile(
        group_id=group_id,
        uploader_id=int(get_jwt_identity()),
        original_filename=upload.filename,
        stored_filename=stored_filename,
        nonce=base64.b64encode(nonce).decode(),
        enc_aes_key=base64.b64encode(aes_key).decode(),
    )
    db.session.add(record)
    db.session.commit()
    return jsonify({"id": record.id, "filename": record.original_filename}), 201