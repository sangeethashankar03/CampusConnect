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
    enc_aes_key_sender = db.Column(db.Text, nullable=True)
    signature = db.Column(db.Text, nullable=False)

    is_file = db.Column(db.Boolean, default=False, nullable=False)
    original_filename = db.Column(db.String(255), nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "sender_id": self.sender_id,
            "receiver_id": self.receiver_id,
            "ciphertext": self.ciphertext,
            "nonce": self.nonce,
            "enc_aes_key": self.enc_aes_key,
            "enc_aes_key_sender": self.enc_aes_key_sender,
            "signature": self.signature,
            "is_file": self.is_file,
            "original_filename": self.original_filename,
            "created_at": self.created_at.isoformat(),
        }


class GroupMessage(db.Model):
    """
    Added: groups previously had file sharing only, no chat at all.
    Same envelope-encryption pattern as file sharing -- one AES key per
    message, wrapped once per member who was in the group at send time
    (see GroupMessageKey). The server stores ciphertext + N wrapped keys
    it can never itself unwrap.
    """
    __tablename__ = "group_messages"

    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey("groups.id"), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    ciphertext = db.Column(db.Text, nullable=False)
    nonce = db.Column(db.String(64), nullable=False)
    signature = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class GroupMessageKey(db.Model):
    __tablename__ = "group_message_keys"

    id = db.Column(db.Integer, primary_key=True)
    group_message_id = db.Column(db.Integer, db.ForeignKey("group_messages.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    wrapped_key = db.Column(db.Text, nullable=False)

    __table_args__ = (db.UniqueConstraint("group_message_id", "user_id", name="uq_group_message_key"),)