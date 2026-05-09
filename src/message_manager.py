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
) -> dict:
    return {
        "sender": sender,
        "receiver": receiver,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "algorithm": {
            "key_exchange": ALGORITMO_TROCA_DE_CHAVES,
            "kdf": ALGORITMO_DERIVACAO_DE_CHAVES,
            "cipher": ALGORITMO_CIFRAGEM,
            "signature": ALGORITMO_ASSINATURA_DIGITAL,
            "hash": ALGORITMO_HASH,
        },
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "signature": signature.hex() if signature else None,
        "hash": hash_value,
    }


def guardar_mensagem_cifrada(
    message_json: dict,
    filename: str | None = None
) -> Path:
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
    nonce = bytes.fromhex(message_json["nonce"])
    ciphertext = bytes.fromhex(message_json["ciphertext"])

    signature = None

    if message_json.get("signature"):
        signature = bytes.fromhex(message_json["signature"])

    return {
        "sender": message_json["sender"],
        "receiver": message_json["receiver"],
        "timestamp": message_json["timestamp"],
        "nonce": nonce,
        "ciphertext": ciphertext,
        "signature": signature,
        "hash": message_json.get("hash"),
        "algorithm": message_json.get("algorithm"),
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