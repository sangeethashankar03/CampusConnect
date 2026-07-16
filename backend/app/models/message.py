from datetime import datetime
from app.extensions import db


class Message(db.Model):
    __tablename__ = "messages"

    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    ciphertext = db.Column(db.Text, nullable=False)
    nonce = db.Column(db.String(64), nullable=False)
    enc_aes_key = db.Column(db.Text, nullable=False)
    signature = db.Column(db.Text, nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "sender_id": self.sender_id,
            "receiver_id": self.receiver_id,
            "ciphertext": self.ciphertext,
            "nonce": self.nonce,
            "enc_aes_key": self.enc_aes_key,
            "signature": self.signature,
            "created_at": self.created_at.isoformat(),
        }