from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
)

from config import PASTA_CHAVES


KEYS_DIR = PASTA_CHAVES


def gerar_par_ed25519(ator: str):
    """
    Gera um par de chaves Ed25519.
    """

    actor_dir = KEYS_DIR / ator
    actor_dir.mkdir(parents=True, exist_ok=True)

    private_key_path = actor_dir / "ed25519_private.pem"
    public_key_path = actor_dir / "ed25519_public.pem"

    if private_key_path.exists() and public_key_path.exists():

        return {
            "ator": ator,
            "private_key": private_key_path,
            "public_key": public_key_path,
        }

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(private_key_path, "wb") as file:
        file.write(private_pem)

    with open(public_key_path, "wb") as file:
        file.write(public_pem)

    return {
        "ator": ator,
        "private_key": private_key_path,
        "public_key": public_key_path,
    }


def gerar_par_x25519(ator: str):
    """
    Gera um par de chaves X25519.
    """

    actor_dir = KEYS_DIR / ator
    actor_dir.mkdir(parents=True, exist_ok=True)

    private_key_path = actor_dir / "x25519_private.pem"
    public_key_path = actor_dir / "x25519_public.pem"

    if private_key_path.exists() and public_key_path.exists():

        return {
            "ator": ator,
            "private_key": private_key_path,
            "public_key": public_key_path,
        }

    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(private_key_path, "wb") as file:
        file.write(private_pem)

    with open(public_key_path, "wb") as file:
        file.write(public_pem)

    return {
        "ator": ator,
        "private_key": private_key_path,
        "public_key": public_key_path,
    }


def carregar_chave_privada(ator: str, tipo: str):
    """
    Carrega uma chave privada PEM.
    """

    private_key_path = KEYS_DIR / ator / f"{tipo}_private.pem"

    if not private_key_path.exists():

        raise FileNotFoundError(
            f"Chave privada não encontrada: {private_key_path}"
        )

    with open(private_key_path, "rb") as file:

        private_key = serialization.load_pem_private_key(
            file.read(),
            password=None,
        )

    return private_key


def carregar_chave_publica(ator: str, tipo: str):
    """
    Carrega uma chave pública PEM.
    """

    public_key_path = KEYS_DIR / ator / f"{tipo}_public.pem"

    if not public_key_path.exists():

        raise FileNotFoundError(
            f"Chave pública não encontrada: {public_key_path}"
        )

    with open(public_key_path, "rb") as file:

        public_key = serialization.load_pem_public_key(
            file.read()
        )

    return public_key