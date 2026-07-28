from datetime import datetime
from app.extensions import db


class PublicKey(db.Model):
    """
    Two RSA key pairs per user, generated once client-side (RSA-OAEP for
    encryption, RSA-PSS for signing). Private keys never reach the server
    in plaintext — enc_private_key_blob / sign_private_key_blob are the
    private keys encrypted client-side with a key derived from the user's
    password (PBKDF2 + AES-GCM), so they can be recovered on a later login
    instead of being regenerated every time (which was the original bug:
    a fresh keypair every login meant old messages became undecryptable).
    """
    __tablename__ = "public_keys"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), unique=True, nullable=False)
    encryption_key_pem = db.Column(db.Text, nullable=False)
    signing_key_pem = db.Column(db.Text, nullable=False)

    # --- Added: encrypted private key backup for persistence across logins ---
    enc_private_key_blob = db.Column(db.Text, nullable=False)
    sign_private_key_blob = db.Column(db.Text, nullable=False)
    kdf_salt = db.Column(db.String(64), nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)