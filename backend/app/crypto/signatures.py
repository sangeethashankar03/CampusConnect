from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

from app.crypto.rsa_utils import load_private_key, load_public_key


def sign_data(private_key_pem: str, data: bytes) -> bytes:
    private_key = load_private_key(private_key_pem)
    return private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


def verify_signature(public_key_pem: str, data: bytes, signature: bytes) -> bool:
    public_key = load_public_key(public_key_pem)
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False