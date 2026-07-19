import os
import uuid

from app.crypto.aes_utils import aes_gcm_encrypt, aes_gcm_decrypt, generate_aes_key

UPLOAD_DIR = "uploads"


def save_encrypted_file(file_bytes: bytes):
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    key = generate_aes_key()
    ciphertext, nonce = aes_gcm_encrypt(key, file_bytes)

    stored_filename = f"{uuid.uuid4().hex}.enc"
    with open(os.path.join(UPLOAD_DIR, stored_filename), "wb") as f:
        f.write(ciphertext)

    return stored_filename, key, nonce


def load_decrypted_file(stored_filename: str, key: bytes, nonce: bytes) -> bytes:
    with open(os.path.join(UPLOAD_DIR, stored_filename), "rb") as f:
        ciphertext = f.read()
    return aes_gcm_decrypt(key, nonce, ciphertext)