from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

def generate_keypair():
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    pk_bytes = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    sk_bytes = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return pk_bytes, sk_bytes

def sign(message: bytes, sk: bytes) -> bytes:
    priv = Ed25519PrivateKey.from_private_bytes(sk)
    return priv.sign(message)

def verify(message: bytes, signature: bytes, pk: bytes):
    pub = Ed25519PublicKey.from_public_bytes(pk)
    pub.verify(signature, message)
