import json
from pathlib import Path
from datetime import datetime, timezone

from config import (
    PASTA_MENSAGENS,
    ALGORITMO_TROCA_DE_CHAVES,
    ALGORITMO_DERIVACAO_DE_CHAVES,
    ALGORITMO_CIFRAGEM,
    ALGORITMO_ASSINATURA_DIGITAL,
    ALGORITMO_HASH,
    CAMPO_REMETENTE,
    CAMPO_DESTINATARIO,
    CAMPO_TIMESTAMP,
    CAMPO_ALGORITMOS,
    CAMPO_NONCE,
    CAMPO_CIPHERTEXT,
    CAMPO_ASSINATURA,
    CAMPO_HASH,
    CAMPO_TIPO_MENSAGEM,
    CAMPO_ID_DOENTE,
)


MESSAGES_DIR = PASTA_MENSAGENS
MESSAGES_DIR.mkdir(parents=True, exist_ok=True)

def criar_json_mensagem(
    sender: str,
    receiver: str,
    nonce: bytes,
    ciphertext: bytes,
    signature: bytes | None = None,
    hash_value: str | None = None,
    timestamp: str | None = None,
    message_type: str | None = None,
    patient_id: str | None = None,
    algorithm: dict | None = None,
) -> dict:
    if timestamp is None:
        timestamp = datetime.now(timezone.utc).isoformat()

    if algorithm is None:
        algorithm = criar_algoritmos_mensagem()

    return {
        CAMPO_REMETENTE: sender,
        CAMPO_DESTINATARIO: receiver,
        CAMPO_TIMESTAMP: timestamp,
        CAMPO_ALGORITMOS: algorithm,
        CAMPO_TIPO_MENSAGEM: message_type,
        CAMPO_ID_DOENTE: patient_id,
        CAMPO_NONCE: nonce.hex(),
        CAMPO_CIPHERTEXT: ciphertext.hex(),
        CAMPO_ASSINATURA: signature.hex() if signature else None,
        CAMPO_HASH: hash_value,
    }


def guardar_mensagem_cifrada(message_json: dict,filename: str | None = None) -> Path:
    if filename is None:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        sender = message_json.get("sender", "unknown")
        receiver = message_json.get("receiver", "unknown")
        filename = f"{timestamp}_{sender}_to_{receiver}.json"

    path = MESSAGES_DIR / filename

    with open(path, "w", encoding="utf-8") as file:
        json.dump(message_json, file, indent=4, ensure_ascii=False)

    return path


def ler_mensagem_recebida(filename: str) -> dict:
    path = MESSAGES_DIR / filename

    if not path.exists():
        raise FileNotFoundError(f"Mensagem não encontrada: {path}")

    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def extrair_campos_mensagem(message_json: dict):
    nonce = bytes.fromhex(message_json[CAMPO_NONCE])
    ciphertext = bytes.fromhex(message_json[CAMPO_CIPHERTEXT])

    signature = None

    if message_json.get(CAMPO_ASSINATURA):
        signature = bytes.fromhex(message_json[CAMPO_ASSINATURA])

    return {
        CAMPO_REMETENTE: message_json[CAMPO_REMETENTE],
        CAMPO_DESTINATARIO: message_json[CAMPO_DESTINATARIO],
        CAMPO_TIMESTAMP: message_json[CAMPO_TIMESTAMP],
        CAMPO_NONCE: nonce,
        CAMPO_CIPHERTEXT: ciphertext,
        CAMPO_ASSINATURA: signature,
        CAMPO_HASH: message_json.get(CAMPO_HASH),
        CAMPO_ALGORITMOS: message_json.get(CAMPO_ALGORITMOS),
        CAMPO_TIPO_MENSAGEM: message_json.get(CAMPO_TIPO_MENSAGEM),
        CAMPO_ID_DOENTE: message_json.get(CAMPO_ID_DOENTE),
    }
    

def criar_algoritmos_mensagem() -> dict:
    """
    Cria a estrutura de algoritmos usada no JSON e no AAD.
    """

    return {
        "key_exchange": ALGORITMO_TROCA_DE_CHAVES,
        "kdf": ALGORITMO_DERIVACAO_DE_CHAVES,
        "cipher": ALGORITMO_CIFRAGEM,
        "signature": ALGORITMO_ASSINATURA_DIGITAL,
        "hash": ALGORITMO_HASH,
    }


def criar_metadados_aad(
    sender: str,
    receiver: str,
    message_type: str | None = None,
    patient_id: str | None = None,
    timestamp: str | None = None,
    algorithm: dict | None = None,
) -> dict:
    """
    Cria os metadados que serão autenticados como AAD no ChaCha20-Poly1305.

    Estes dados não são cifrados, mas qualquer alteração posterior fará
    falhar a autenticação da mensagem.
    """

    if timestamp is None:
        timestamp = datetime.now(timezone.utc).isoformat()

    if algorithm is None:
        algorithm = criar_algoritmos_mensagem()

    return {
        CAMPO_REMETENTE: sender,
        CAMPO_DESTINATARIO: receiver,
        CAMPO_TIMESTAMP: timestamp,
        CAMPO_ALGORITMOS: algorithm,
        CAMPO_TIPO_MENSAGEM: message_type,
        CAMPO_ID_DOENTE: patient_id,
    }


def serializar_aad_canonico(metadata: dict) -> bytes:
    """
    Serializa os metadados de forma canónica para uso como AAD.

    A ordenação das chaves e os separadores fixos garantem que a mesma
    estrutura produz sempre os mesmos bytes.
    """

    return json.dumps(
        metadata,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False
    ).encode("utf-8")


def obter_metadados_aad_de_json(message_json: dict) -> dict:
    """
    Reconstrói os metadados AAD a partir de uma mensagem JSON recebida.
    """

    return {
        CAMPO_REMETENTE: message_json.get(CAMPO_REMETENTE),
        CAMPO_DESTINATARIO: message_json.get(CAMPO_DESTINATARIO),
        CAMPO_TIMESTAMP: message_json.get(CAMPO_TIMESTAMP),
        CAMPO_ALGORITMOS: message_json.get(CAMPO_ALGORITMOS),
        CAMPO_TIPO_MENSAGEM: message_json.get(CAMPO_TIPO_MENSAGEM),
        CAMPO_ID_DOENTE: message_json.get(CAMPO_ID_DOENTE),
    }



def listar_mensagens(receiver: str | None = None) -> list[Path]:

    MESSAGES_DIR.mkdir(parents=True, exist_ok=True)

    mensagens = sorted(
        MESSAGES_DIR.glob("*.json"),
        key=lambda path: path.stat().st_mtime,
        reverse=True
    )

    if receiver is None:
        return mensagens

    mensagens_filtradas = []

    for path in mensagens:
        try:
            with open(path, "r", encoding="utf-8") as file:
                message_json = json.load(file)

            if message_json.get("receiver") == receiver:
                mensagens_filtradas.append(path)

        except Exception:
            continue

    return mensagens_filtradas

    