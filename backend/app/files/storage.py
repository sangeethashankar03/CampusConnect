import os
import uuid
from flask import current_app


def save_ciphertext_blob(ciphertext_bytes: bytes) -> str:
    """
    The bytes here are ALREADY AES-GCM ciphertext produced client-side.
    This replaces the old version of this function, which generated the
    AES key on the SERVER and encrypted here -- meaning plaintext arrived
    over the network and the server held the only copy of the key. This
    version never sees plaintext and never touches a key; it's pure
    storage, same as if it were writing to Azure Blob Storage.
    """
    upload_dir = current_app.config["UPLOAD_FOLDER"]
    os.makedirs(upload_dir, exist_ok=True)
    stored_filename = f"{uuid.uuid4().hex}.enc"
    with open(os.path.join(upload_dir, stored_filename), "wb") as f:
        f.write(ciphertext_bytes)
    return stored_filename


def load_ciphertext_blob(stored_filename: str) -> bytes:
    upload_dir = current_app.config["UPLOAD_FOLDER"]
    with open(os.path.join(upload_dir, stored_filename), "rb") as f:
        return f.read()