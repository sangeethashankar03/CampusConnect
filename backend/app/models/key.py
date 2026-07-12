from datetime import datetime
from app.extensions import db


class PublicKey(db.Model):
    """
    Two separate RSA key pairs are used per user, generated client-side:
      - an RSA-OAEP pair for encrypting AES session keys
      - an RSA-PSS pair for signing messages
    WebCrypto does not allow one key pair to be used for both purposes,
    so we store both public keys here. Private keys never reach the server.
    """
    __tablename__ = "public_keys"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), unique=True, nullable=False)
    encryption_key_pem = db.Column(db.Text, nullable=False)
    signing_key_pem = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)