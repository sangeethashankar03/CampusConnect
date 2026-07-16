import base64

REQUIRED_FIELDS = ["receiver_id", "ciphertext", "nonce", "enc_aes_key", "signature"]


def validate_encrypted_payload(data: dict):
    missing = [f for f in REQUIRED_FIELDS if not data.get(f)]
    if missing:
        return False, f"Missing fields: {', '.join(missing)}"

    for field in ("ciphertext", "nonce", "enc_aes_key", "signature"):
        try:
            base64.b64decode(data[field], validate=True)
        except Exception:
            return False, f"Field '{field}' must be valid base64"

    return True, None