# src/config.py

from pathlib import Path

# Diretório base do projeto
BASE_DIR = Path(__file__).resolve().parent.parent

# Diretórios principais
DATA_DIR = BASE_DIR / "data"
KEYS_DIR = DATA_DIR / "keys"
MESSAGES_DIR = DATA_DIR / "messages"

# Diretórios de mensagens
INBOX_DIR = MESSAGES_DIR / "inbox"
OUTBOX_DIR = MESSAGES_DIR / "outbox"

# Utilizadores de teste
USER_CARLA = "carla"
USER_RUI = "rui"

# Parâmetros criptográficos
RSA_KEY_SIZE = 2048
AES_KEY_SIZE = 32  # 32 bytes = AES-256 Extensões dos ficheiros PRIVATE_KEY_FILE = "private_key.pem" PUBLIC_KEY_FILE = "public_key.pem" MESSAGE_EXTENSION = ".msg"
ENCRYPTED_EXTENSION = ".enc"
SIGNATURE_EXTENSION = ".sig"


def create_required_directories():
    """
    Cria as pastas necessárias caso ainda não existam.
    """
    DATA_DIR.mkdir(exist_ok=True)
    KEYS_DIR.mkdir(exist_ok=True)
    MESSAGES_DIR.mkdir(exist_ok=True)
    INBOX_DIR.mkdir(exist_ok=True)
    OUTBOX_DIR.mkdir(exist_ok=True)

    (KEYS_DIR / USER_CARLA).mkdir(exist_ok=True)
    (KEYS_DIR / USER_RUI).mkdir(exist_ok=True)
