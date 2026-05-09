from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


BASE_DIR = Path(__file__).resolve().parent.parent
KEYS_DIR = BASE_DIR / "data" / "keys"


def gerar_par_rsa(ator: str, key_size: int = 2048, overwrite: bool = False):
    """
    Gera um par de chaves RSA para um ator e guarda em PEM.

    Exemplo:
        gerar_par_rsa("rui")
        gerar_par_rsa("carla")
    """

    actor_dir = KEYS_DIR / ator
    actor_dir.mkdir(parents=True, exist_ok=True)

    private_key_path = actor_dir / "private_key.pem"
    public_key_path = actor_dir / "public_key.pem"


    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )

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

    with open(private_key_path, "wb") as f:
        f.write(private_pem)

    with open(public_key_path, "wb") as f:
        f.write(public_pem)

    return {
        "ator": ator,
        "private_key": private_key_path,
        "public_key": public_key_path,
    }


def carregar_chave_privada(ator: str):
    """
    Carrega a chave privada RSA de um ator a partir do ficheiro PEM.

    Exemplo:
        private_key = carregar_chave_privada("rui")
    """

    private_key_path = KEYS_DIR / ator / "private_key.pem"

    if not private_key_path.exists():
        raise FileNotFoundError(f"Chave privada não encontrada: {private_key_path}")

    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
        )

    return private_key


def carregar_chave_publica(ator: str):
    """
    Carrega a chave pública RSA de um ator a partir do ficheiro PEM.

    Exemplo:
        public_key = carregar_chave_publica("carla")
    """

    public_key_path = KEYS_DIR / ator / "public_key.pem"

    if not public_key_path.exists():
        raise FileNotFoundError(f"Chave pública não encontrada: {public_key_path}")

    with open(public_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(
            f.read()
        )

    return public_key