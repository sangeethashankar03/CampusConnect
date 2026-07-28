from datetime import datetime
from app.extensions import db


class SharedFile(db.Model):
    __tablename__ = "shared_files"

    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey("groups.id"), nullable=False)
    uploader_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    original_filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(255), nullable=False)
    nonce = db.Column(db.String(64), nullable=False)
    # NOTE: the old single `enc_aes_key` column is REMOVED. It was never
    # actually RSA-encrypted despite the name -- it stored the raw AES key,
    # generated server-side, so the server (or anyone with DB access) could
    # decrypt every file. See FileKey below for the real fix.

    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)


class FileKey(db.Model):
    """
    Added: envelope encryption. The file is encrypted client-side with a
    one-off AES-256-GCM key; that same key is then RSA-OAEP-wrapped once per
    group member's public key. One row per (file, member). The server
    stores N wrapped copies of a key it can never itself unwrap -- it never
    generates the key and never sees a plaintext copy of it.
    """
    __tablename__ = "file_keys"

    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey("shared_files.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    wrapped_key = db.Column(db.Text, nullable=False)

    __table_args__ = (db.UniqueConstraint("file_id", "user_id", name="uq_file_key"),)