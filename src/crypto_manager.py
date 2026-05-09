import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


def encrypt_message_ChaCha20Poly1305(message: str, key: bytes):
    """
    Encripta uma mensagem usando ChaCha20-Poly1305.

    Args:
        message (str): mensagem em texto
        key (bytes): chave de 32 bytes

    Returns:
        tuple: (nonce, ciphertext)
    """
 # cada msg tem um noce unico
    nonce = os.urandom(12)

    chacha = ChaCha20Poly1305(key)

    ciphertext = chacha.encrypt(
        nonce=nonce,
        data=message.encode(),
        associated_data=None
    )

    return nonce, ciphertext


def decrypt_message_ChaCha20Poly1305(nonce: bytes, ciphertext: bytes, key: bytes):
    """
    Desencripta uma mensagem ChaCha20-Poly1305.

    Args:
        nonce (bytes): nonce usado na cifra
        ciphertext (bytes): mensagem cifrada
        key (bytes): chave de 32 bytes

    Returns:
        str: mensagem original
    """

    chacha = ChaCha20Poly1305(key)

    plaintext = chacha.decrypt(
        nonce=nonce,
        data=ciphertext,
        associated_data=None
    )

    return plaintext.decode()