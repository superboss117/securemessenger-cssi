from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def derive_shared_secret(
    my_private_key: X25519PrivateKey,
    peer_public_key: X25519PublicKey
) -> bytes:
    """
    Gera o segredo partilhado X25519 entre a minha chave privada
    e a chave pública do outro utilizador.
    """
    return my_private_key.exchange(peer_public_key)


def derive_chacha20_key(shared_secret: bytes, salt: bytes | None = None) -> bytes:
    """
    Deriva uma chave simétrica de 32 bytes para ChaCha20-Poly1305.
    """
    v
    return HKDF(algorithm=hashes.SHA256(),length=32,salt=salt,info=b"securemessenger-chacha20-key",).derive(shared_secret)