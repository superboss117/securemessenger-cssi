import os
import getpass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from config import PASTA_CHAVES


KEYS_DIR = PASTA_CHAVES

ENV_KEY_PASSWORD = "SECUREMESSENGER_KEY_PASSWORD"

_KEY_PASSWORD_CACHE: bytes | None = None



def gerar_par_ed25519(ator: str, password:str |bytes | None=None,):

    """
    Gera um par de chaves Ed25519.

    A chave privada é guardada em PEM encriptado com password.
    A chave pública é guardada em PEM sem encriptação.
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
    
    password_bytes = obter_password_chaves(confirmar=True,password=password)

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password_bytes),
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

def gerar_par_x25519(ator: str,password: str | bytes | None = None,):
    """
    Gera um par de chaves X25519.

    A chave privada é guardada em PEM encriptado com password.
    A chave pública é guardada em PEM sem encriptação.
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

    password_bytes = obter_password_chaves(
        confirmar=True,
        password=password,
    )

    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            password_bytes
        ),
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
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

def carregar_chave_privada(ator: str,tipo: str,
    password: str | bytes | None = None,):
    """
    Carrega uma chave privada PEM encriptada.

    Args:
        ator: nome do ator, por exemplo "carla" ou "rui".
        tipo: "ed25519" ou "x25519".
        password: password opcional. Se None, será obtida por variável
                  de ambiente ou por prompt interativo.

    Returns:
        Objeto de chave privada Ed25519 ou X25519.
    """

    private_key_path = KEYS_DIR / ator / f"{tipo}_private.pem"

    if not private_key_path.exists():
        raise FileNotFoundError(
            f"Chave privada não encontrada: {private_key_path}"
        )

    password_bytes = obter_password_chaves(
        confirmar=False,
        password=password,
    )

    with open(private_key_path, "rb") as file:
        private_key_data = file.read()

    try:
        private_key = serialization.load_pem_private_key(
            private_key_data,
            password=password_bytes,
        )
    except TypeError as exc:
        raise TypeError(
            "Falha ao carregar a chave privada. "
            "A chave pode estar em formato antigo sem encriptação, "
            "ou a password foi fornecida para uma chave não encriptada. "
            "Recomenda-se regenerar as chaves privadas."
        ) from exc
    except ValueError as exc:
        raise ValueError(
            "Falha ao carregar a chave privada. "
            "Password incorreta ou ficheiro PEM inválido."
        ) from exc

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


def _normalizar_password(password: str | bytes) -> bytes:
    """
    Converte a password para bytes UTF-8 e aplica validações simples.
    """

    if isinstance(password, bytes):
        password_bytes = password
    elif isinstance(password, str):
        password_bytes = password.encode("utf-8")
    else:
        raise TypeError("A password deve ser str ou bytes.")

    if len(password_bytes) < 8:
        raise ValueError(
            "A password das chaves deve ter pelo menos 8 bytes/caracteres."
        )

    return password_bytes


def obter_password_chaves(
    confirmar: bool = False,
    password: str | bytes | None = None,) -> bytes:
    """
    Obtém a password usada para proteger/carregar chaves privadas.

    Ordem de obtenção:
    1. password passada diretamente como argumento;
    2. variável de ambiente SECUREMESSENGER_KEY_PASSWORD;
    3. prompt interativo com getpass.

    A password é mantida em cache durante a execução para evitar pedir
    repetidamente a mesma password.
    """

    global _KEY_PASSWORD_CACHE

    if password is not None:
        return _normalizar_password(password)

    if _KEY_PASSWORD_CACHE is not None:
        return _KEY_PASSWORD_CACHE

    password_env = os.environ.get(ENV_KEY_PASSWORD)

    if password_env:
        _KEY_PASSWORD_CACHE = _normalizar_password(password_env)
        return _KEY_PASSWORD_CACHE

    while True:
        password_1 = getpass.getpass("Password das chaves privadas: ")

        if confirmar:
            password_2 = getpass.getpass("Confirmar password: ")

            if password_1 != password_2:
                print("[ERRO] As passwords não coincidem. Tenta novamente.")
                continue

        try:
            _KEY_PASSWORD_CACHE = _normalizar_password(password_1)
            return _KEY_PASSWORD_CACHE
        except ValueError as exc:
            print(f"[ERRO] {exc}")