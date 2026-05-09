from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature


def sign_message(private_key: Ed25519PrivateKey,message) -> bytes:
    """
    Assina uma mensagem com Ed25519.

    Args:
        private_key: chave privada Ed25519.
        message: mensagem.

    Returns:
        assinatura em bytes.
    """
    message = message.encode("utf-8")
    signature = private_key.sign(message)

    return signature


def verify_signature(public_key: Ed25519PublicKey,message,signature: bytes) -> bool:
    """
    Verifica uma assinatura Ed25519.

    Args:
        public_key: chave pública Ed25519.
        message: mensagem original.
        signature: assinatura em bytes.

    Returns:
        True se a assinatura for válida, False se for inválida.
    """
    message = message.encode("utf-8")

    try:
        public_key.verify(signature, message)
        return True

    except InvalidSignature:
        return False