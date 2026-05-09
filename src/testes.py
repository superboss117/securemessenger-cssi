import json
from pathlib import Path

from message_manager import listar_mensagens


def escolher_mensagem() -> Path | None:
    mensagens = listar_mensagens()

    if not mensagens:
        print("\n[INFO] Não existem mensagens em data/messages.")
        return None

    print("\nMensagens disponíveis:")

    for i, path in enumerate(mensagens, start=1):
        print(f"{i}. {path.name}")

    try:
        escolha = int(input("\nEscolha a mensagem: "))

        if escolha < 1 or escolha > len(mensagens):
            print("[ERRO] Opção inválida.")
            return None

        return mensagens[escolha - 1]

    except ValueError:
        print("[ERRO] Introduza um número.")
        return None


def carregar_json(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def guardar_json(path: Path, data: dict):
    with open(path, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4, ensure_ascii=False)


def alterar_hex(valor: str) -> str:
    """
    Altera o primeiro byte hexadecimal sem destruir o formato.
    """

    if len(valor) < 2:
        return "00"

    if valor[:2].lower() == "ff":
        return "00" + valor[2:]

    return "ff" + valor[2:]


def guardar_copia_corrompida(path_original: Path, data: dict, sufixo: str):
    novo_nome = path_original.stem + f"_{sufixo}" + path_original.suffix
    novo_path = path_original.parent / novo_nome

    guardar_json(novo_path, data)

    print("\n[OK] Ficheiro de teste criado:")
    print(novo_path)


def corromper_ciphertext():
    path = escolher_mensagem()

    if path is None:
        return

    data = carregar_json(path)

    data["ciphertext"] = alterar_hex(data["ciphertext"])

    guardar_copia_corrompida(path, data, "ciphertext_corrompido")


def corromper_nonce():
    path = escolher_mensagem()

    if path is None:
        return

    data = carregar_json(path)

    data["nonce"] = alterar_hex(data["nonce"])

    guardar_copia_corrompida(path, data, "nonce_corrompido")


def corromper_assinatura():
    path = escolher_mensagem()

    if path is None:
        return

    data = carregar_json(path)

    if not data.get("signature"):
        print("[ERRO] Esta mensagem não tem assinatura.")
        return

    data["signature"] = alterar_hex(data["signature"])

    guardar_copia_corrompida(path, data, "assinatura_corrompida")


def corromper_hash():
    path = escolher_mensagem()

    if path is None:
        return

    data = carregar_json(path)

    if not data.get("hash"):
        print("[ERRO] Esta mensagem não tem hash.")
        return

    data["hash"] = alterar_hex(data["hash"])

    guardar_copia_corrompida(path, data, "hash_corrompida")


def falsificar_sender():
    path = escolher_mensagem()

    if path is None:
        return

    data = carregar_json(path)

    data["sender"] = "pedro"

    guardar_copia_corrompida(path, data, "sender_falsificado")


def trocar_destinatario():
    path = escolher_mensagem()

    if path is None:
        return

    data = carregar_json(path)

    data["receiver"] = "carla"

    guardar_copia_corrompida(path, data, "receiver_errado")


def menu_testes():
    while True:
        print("\n==============================")
        print(" TESTES DE SEGURANÇA ")
        print("==============================")
        print("1. Corromper ciphertext")
        print("2. Corromper nonce")
        print("3. Corromper assinatura")
        print("4. Corromper hash")
        print("5. Falsificar remetente")
        print("6. Trocar destinatário")
        print("7. Voltar")
        print("==============================")

        opcao = input("Escolha uma opção: ")

        if opcao == "1":
            corromper_ciphertext()

        elif opcao == "2":
            corromper_nonce()

        elif opcao == "3":
            corromper_assinatura()

        elif opcao == "4":
            corromper_hash()

        elif opcao == "5":
            falsificar_sender()

        elif opcao == "6":
            trocar_destinatario()

        elif opcao == "7":
            break

        else:
            print("[ERRO] Opção inválida.")


if __name__ == "__main__":
    menu_testes()