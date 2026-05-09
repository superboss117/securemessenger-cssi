from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from cryptography.exceptions import InvalidSignature


def sign_message(
    private_key: Ed25519PrivateKey,
    message: str
) -> bytes:

    # A assinatura é calculada sobre bytes UTF-8 para garantir
    # representação consistente da mensagem entre sistemas.
    message_bytes = message.encode("utf-8")

    signature = private_key.sign(
        message_bytes
    )

    return signature


def verify_signature(
    public_key: Ed25519PublicKey,
    message: str,
    signature: bytes
) -> bool:
    """
    Verifica uma assinatura digital Ed25519.

    Args:
        public_key:
            Chave pública Ed25519.

        message:
            Mensagem original.

        signature:
            Assinatura digital.

    Returns:
        True se a assinatura for válida.
        False se a assinatura for inválida.
    """

    message_bytes = message.encode("utf-8")

    try:

        public_key.verify(
            signature,
            message_bytes
        )

        return True

    # A biblioteca lança InvalidSignature quando a verificação falha.
    # O sistema converte esse comportamento para booleano para simplificar
    # a lógica do fluxo clínico.
    except InvalidSignature:

        return False