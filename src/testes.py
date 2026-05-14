import json
import os
from pathlib import Path
from datetime import datetime, timezone

from config import PASTA_MENSAGENS


MESSAGES_DIR = PASTA_MENSAGENS
MESSAGES_DIR.mkdir(parents=True, exist_ok=True)


# =========================================================
# FUNÇÕES BASE
# =========================================================

def listar_ficheiros_mensagem() -> list[Path]:
    """
    Lista todos os ficheiros JSON da pasta de mensagens.
    """

    return sorted(
        MESSAGES_DIR.glob("*.json"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )


def carregar_json(path: Path) -> dict:
    """
    Carrega uma mensagem JSON.
    """

    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def guardar_json(path: Path, data: dict):
    """
    Guarda um JSON formatado.
    """

    with open(path, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4, ensure_ascii=False)


def mostrar_resumo_mensagem(index: int, path: Path):
    """
    Mostra uma linha de resumo da mensagem.
    """

    try:
        data = carregar_json(path)

        print(
            f"{index}. "
            f"{data.get('timestamp')} | "
            f"De: {data.get('sender')} | "
            f"Para: {data.get('receiver')} | "
            f"Tipo: {data.get('message_type')} | "
            f"Doente: {data.get('patient_id')} | "
            f"Ficheiro: {path.name}"
        )

    except Exception:
        print(f"{index}. [ERRO AO LER] {path.name}")


def escolher_mensagem() -> Path | None:
    """
    Permite ao utilizador escolher uma mensagem JSON existente.
    """

    mensagens = listar_ficheiros_mensagem()

    if not mensagens:
        print("\n[INFO] Não existem mensagens JSON em data/messages.")
        return None

    print("\nMensagens disponíveis:")

    for i, path in enumerate(mensagens, start=1):
        mostrar_resumo_mensagem(i, path)

    try:
        escolha = int(input("\nEscolha a mensagem para corromper: ").strip())
    except ValueError:
        print("[ERRO] Introduza um número.")
        return None

    if escolha < 1 or escolha > len(mensagens):
        print("[ERRO] Opção inválida.")
        return None

    return mensagens[escolha - 1]


def nome_copia_teste(path_original: Path, sufixo: str) -> Path:
    """
    Cria um nome único para uma cópia de teste.
    """

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    novo_nome = f"{path_original.stem}__TESTE_{sufixo}_{timestamp}{path_original.suffix}"

    return path_original.parent / novo_nome


def guardar_copia_corrompida(path_original: Path, data: dict, sufixo: str):
    """
    Guarda uma cópia corrompida da mensagem original.
    """

    novo_path = nome_copia_teste(path_original, sufixo)

    guardar_json(novo_path, data)

    print("\n[OK] Ficheiro de teste criado:")
    print(novo_path)
    print("\nAgora tenta abrir este ficheiro pelo menu do Enf. Rui.")
    print("A mensagem deve ser rejeitada pelo sistema.")


# =========================================================
# FUNÇÕES DE ALTERAÇÃO
# =========================================================

def alterar_hex(valor: str | None) -> str:
    """
    Altera o primeiro byte hexadecimal sem destruir o formato.

    Exemplo:
        abcd -> ffcd
        ffcd -> 00cd
    """

    if not isinstance(valor, str) or len(valor) < 2:
        return "00"

    if valor[:2].lower() == "ff":
        return "00" + valor[2:]

    return "ff" + valor[2:]


def alterar_texto(valor: str | None, novo_valor_base: str) -> str:
    """
    Altera um campo textual.
    """

    if not valor:
        return novo_valor_base

    return f"{valor}_alterado_teste"


def alterar_timestamp(valor: str | None) -> str:
    """
    Altera o timestamp preservando formato textual ISO aproximado.
    """

    return "2099-01-01T00:00:00+00:00"


def alterar_algorithm(algorithm):
    """
    Altera a estrutura de algoritmos.

    O campo algorithm faz parte dos metadados da mensagem.
    Se o envelope assinado estiver correto, esta alteração deve
    invalidar a assinatura.
    """

    if not isinstance(algorithm, dict):
        return {
            "key_exchange": "X25519",
            "kdf": "HKDF-SHA256",
            "cipher": "AES-GCM-ALTERADO",
            "signature": "Ed25519",
            "hash": "BLAKE2b",
        }

    novo_algorithm = dict(algorithm)

    cipher_atual = novo_algorithm.get("cipher")

    if cipher_atual == "ChaCha20-Poly1305":
        novo_algorithm["cipher"] = "ChaCha20-Poly1305-ALTERADO"
    else:
        novo_algorithm["cipher"] = "ChaCha20-Poly1305"

    return novo_algorithm


# =========================================================
# TESTES DE CORRUPÇÃO
# =========================================================

def corromper_ciphertext():
    """
    Corrompe o ciphertext.

    Esperado:
    - assinatura inválida, se o envelope cobre ciphertext;
    - ou erro ChaCha20-Poly1305, se chegar à decifragem.
    """

    path = escolher_mensagem()

    if path is None:
        return

    data = carregar_json(path)

    if "ciphertext" not in data:
        print("[ERRO] A mensagem não contém campo ciphertext.")
        return

    data["ciphertext"] = alterar_hex(data.get("ciphertext"))

    guardar_copia_corrompida(path, data, "ciphertext_corrompido")


def corromper_nonce():
    """
    Corrompe o nonce.

    O nonce é necessário para ChaCha20-Poly1305.
    Alterá-lo deve invalidar a assinatura do envelope ou a tag AEAD.
    """

    path = escolher_mensagem()

    if path is None:
        return

    data = carregar_json(path)

    if "nonce" not in data:
        print("[ERRO] A mensagem não contém campo nonce.")
        return

    data["nonce"] = alterar_hex(data.get("nonce"))

    guardar_copia_corrompida(path, data, "nonce_corrompido")


def corromper_assinatura():
    """
    Corrompe a assinatura Ed25519.

    Esperado:
    - rejeição por assinatura inválida.
    """

    path = escolher_mensagem()

    if path is None:
        return

    data = carregar_json(path)

    if not data.get("signature"):
        print("[ERRO] Esta mensagem não tem assinatura.")
        return

    data["signature"] = alterar_hex(data.get("signature"))

    guardar_copia_corrompida(path, data, "assinatura_corrompida")


def remover_assinatura():
    """
    Remove a assinatura digital.

    Esperado:
    - rejeição imediata por ausência de assinatura.
    """

    path = escolher_mensagem()

    if path is None:
        return

    data = carregar_json(path)

    data["signature"] = None

    guardar_copia_corrompida(path, data, "assinatura_removida")


def corromper_hash():
    """
    Corrompe a hash BLAKE2b.

    A hash é calculada com BLAKE2b de 64 bytes no projeto [8].
    Se a hash estiver no envelope assinado, a assinatura deve falhar.
    Caso contrário, deve falhar a validação final da hash.
    """

    path = escolher_mensagem()

    if path is None:
        return

    data = carregar_json(path)

    if not data.get("hash"):
        print("[ERRO] Esta mensagem não tem hash.")
        return

    data["hash"] = alterar_hex(data.get("hash"))

    guardar_copia_corrompida(path, data, "hash_corrompida")


def falsificar_sender():
    """
    Altera o remetente.

    Esperado:
    - rejeição porque sender deixa de ser carla;
    - ou assinatura inválida, se for validada antes.
    """

    path = escolher_mensagem()

    if path is None:
        return

    data = carregar_json(path)

    data["sender"] = "pedro"

    guardar_copia_corrompida(path, data, "sender_falsificado")


def trocar_destinatario():
    """
    Altera o destinatário.

    Esperado:
    - rejeição porque receiver deixa de ser rui;
    - ou assinatura inválida.
    """

    path = escolher_mensagem()

    if path is None:
        return

    data = carregar_json(path)

    data["receiver"] = "carla"

    guardar_copia_corrompida(path, data, "receiver_errado")


def corromper_message_type():
    """
    Altera o tipo de mensagem.

    O campo message_type existe na configuração como campo JSON relevante [4].
    Como faz parte dos metadados/AAD/envelope, a mensagem deve ser rejeitada.
    """

    path = escolher_mensagem()

    if path is None:
        return

    data = carregar_json(path)

    data["message_type"] = alterar_texto(
        data.get("message_type"),
        "tipo_falso",
    )

    guardar_copia_corrompida(path, data, "message_type_corrompido")


def corromper_patient_id():
    """
    Altera o patient_id.

    O campo patient_id existe na configuração como campo JSON relevante [4].
    Como faz parte dos metadados/AAD/envelope, a mensagem deve ser rejeitada.
    """

    path = escolher_mensagem()

    if path is None:
        return

    data = carregar_json(path)

    data["patient_id"] = alterar_texto(
        data.get("patient_id"),
        "999999",
    )

    guardar_copia_corrompida(path, data, "patient_id_corrompido")


def corromper_timestamp():
    """
    Altera o timestamp.

    Como o timestamp entra nos metadados autenticados, a mensagem deve
    ser rejeitada.
    """

    path = escolher_mensagem()

    if path is None:
        return

    data = carregar_json(path)

    data["timestamp"] = alterar_timestamp(data.get("timestamp"))

    guardar_copia_corrompida(path, data, "timestamp_corrompido")


def corromper_salt():
    """
    Altera o salt usado no HKDF.

    O salt entra na derivação HKDF da chave ChaCha20-Poly1305.
    A função derive_chacha20_key aceita salt explicitamente [1].

    Esperado:
    - assinatura inválida, se o salt estiver no envelope assinado;
    - ou falha de decifragem, porque a chave derivada muda.
    """

    path = escolher_mensagem()

    if path is None:
        return

    data = carregar_json(path)

    if not data.get("salt"):
        print("[ERRO] Esta mensagem não tem campo salt.")
        print("Provavelmente é uma mensagem antiga.")
        return

    data["salt"] = alterar_hex(data.get("salt"))

    guardar_copia_corrompida(path, data, "salt_corrompido")


def corromper_algorithm():
    """
    Altera o campo algorithm.

    O JSON da mensagem inclui metadados de algoritmos, como cipher, kdf,
    signature e hash [3]. Se o envelope assinado cobre este campo,
    a assinatura deve falhar.
    """

    path = escolher_mensagem()

    if path is None:
        return

    data = carregar_json(path)

    data["algorithm"] = alterar_algorithm(data.get("algorithm"))

    guardar_copia_corrompida(path, data, "algorithm_corrompido")


# =========================================================
# TESTE DE MENSAGEM FALSA
# =========================================================

def criar_mensagem_falsa_carla():
    """
    Cria uma mensagem falsa na pasta partilhada dizendo ser da Carla.

    Este teste simula um atacante que consegue escrever na pasta de mensagens,
    mas não tem a chave privada Ed25519 da Carla.

    Esperado:
    - rejeição por assinatura inválida;
    - ou rejeição por erro de integridade/autenticidade.
    """

    timestamp_nome = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    timestamp_json = datetime.now(timezone.utc).isoformat()

    fake_message = {
        "sender": "carla",
        "receiver": "rui",
        "timestamp": timestamp_json,
        "algorithm": {
            "key_exchange": "X25519",
            "kdf": "HKDF-SHA256",
            "cipher": "ChaCha20-Poly1305",
            "signature": "Ed25519",
            "hash": "BLAKE2b",
        },
        "message_type": "resultado_urgente",
        "patient_id": "999",
        "nonce": os.urandom(12).hex(),
        "ciphertext": os.urandom(64).hex(),
        "salt": os.urandom(16).hex(),
        "signature": os.urandom(64).hex(),
        "hash": os.urandom(64).hex(),
    }

    filename = f"{timestamp_nome}_fake_carla_to_rui.json"
    path = MESSAGES_DIR / filename

    guardar_json(path, fake_message)

    print("\n[OK] Mensagem falsa criada:")
    print(path)
    print("\nEste ficheiro diz ser da Carla, mas não tem uma assinatura válida.")
    print("Ao abrir no menu do Enf. Rui, deve ser rejeitado.")


# =========================================================
# MENU
# =========================================================

def menu_testes():
    while True:
        print("\n==============================")
        print(" TESTES DE SEGURANÇA ")
        print("==============================")
        print("1. Corromper ciphertext")
        print("2. Corromper nonce")
        print("3. Corromper assinatura")
        print("4. Remover assinatura")
        print("5. Corromper hash")
        print("6. Falsificar remetente")
        print("7. Trocar destinatário")
        print("8. Corromper tipo de mensagem")
        print("9. Corromper patient_id")
        print("10. Corromper timestamp")
        print("11. Corromper salt")
        print("12. Corromper algorithm")
        print("13. Criar mensagem falsa como se fosse da Carla")
        print("14. Sair")
        print("==============================")

        opcao = input("Escolha uma opção: ").strip()

        if opcao == "1":
            corromper_ciphertext()

        elif opcao == "2":
            corromper_nonce()

        elif opcao == "3":
            corromper_assinatura()

        elif opcao == "4":
            remover_assinatura()

        elif opcao == "5":
            corromper_hash()

        elif opcao == "6":
            falsificar_sender()

        elif opcao == "7":
            trocar_destinatario()

        elif opcao == "8":
            corromper_message_type()

        elif opcao == "9":
            corromper_patient_id()

        elif opcao == "10":
            corromper_timestamp()

        elif opcao == "11":
            corromper_salt()

        elif opcao == "12":
            corromper_algorithm()

        elif opcao == "13":
            criar_mensagem_falsa_carla()

        elif opcao == "14":
            print("\nA sair dos testes...")
            break

        else:
            print("[ERRO] Opção inválida.")


if __name__ == "__main__":
    menu_testes()