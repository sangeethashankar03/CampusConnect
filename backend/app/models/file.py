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
    enc_aes_key = db.Column(db.Text, nullable=False)

    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)