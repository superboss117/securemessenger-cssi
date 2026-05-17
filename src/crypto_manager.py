import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


def encrypt_message_ChaCha20Poly1305(message: str, key: bytes,associated_data: bytes | None = None):
    
    #Encripta uma mensagem usando ChaCha20-Poly1305.

   
    # cada msg tem um noce unico
    nonce = os.urandom(12)

    chacha = ChaCha20Poly1305(key)

    ciphertext = chacha.encrypt(
        nonce=nonce,
        data=message.encode("utf-8"),
        associated_data=associated_data
    )

    return nonce, ciphertext


def decrypt_message_ChaCha20Poly1305(nonce: bytes, ciphertext: bytes, key: bytes, associated_data: bytes | None = None):

    #Desencripta mensagem com ChaCha20-Poly1305.

    chacha = ChaCha20Poly1305(key)

    plaintext = chacha.decrypt(
        nonce=nonce,
        data=ciphertext,
        associated_data=associated_data
    )

    return plaintext.decode("utf-8")