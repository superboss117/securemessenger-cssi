from key_manager import (
    gerar_par_ed25519,
    gerar_par_x25519,
    carregar_chave_privada,
    carregar_chave_publica,
)

from hash_manager import calcular_hash_blake2b
from signature_manager import sign_message, verify_signature
from x25519_manager import derive_shared_secret, derive_chacha20_key

from crypto_manager import (
    encrypt_message_ChaCha20Poly1305,
    decrypt_message_ChaCha20Poly1305,
)

from message_manager import (
    criar_json_mensagem,
    guardar_mensagem_cifrada,
    ler_mensagem_recebida,
    extrair_campos_mensagem,
    listar_mensagens,
    criar_metadados_aad,
    serializar_aad_canonico,
    obter_metadados_aad_de_json,
    serializar_envelope_assinavel_canonico,
)

from cryptography.exceptions import InvalidTag

from config import (
    DRA_CARLA,
    ENF_RUI,
    NOME_DO_SISTEMA,
    TIPOS_MENSAGEM,
)



def gerar_chaves_atores():
    print("\n--- GESTÃO DE CHAVES ---")

    gerar_par_ed25519(DRA_CARLA)
    gerar_par_x25519(DRA_CARLA)

    gerar_par_ed25519(ENF_RUI)
    gerar_par_x25519(ENF_RUI)

    print("\n[OK] Chaves geridas com sucesso.")


def carla_preparar_mensagem():
    print("\n--- DRA. CARLA: PREPARAR MENSAGEM SEGURA ---")

    tipo = escolher_tipo_mensagem()

    paciente_id = input("ID do doente: ").strip()

    if not paciente_id:
        print("[ERRO] O ID do doente é obrigatório.")
        return

    conteudo = input("Conteúdo clínico da mensagem: ").strip()

    if not conteudo:
        print("[ERRO] O conteúdo clínico é obrigatório.")
        return

    sender = DRA_CARLA
    receiver = ENF_RUI

    dados_para_assinar = (
        f"sender={sender};"
        f"receiver={receiver};"
        f"tipo={tipo};"
        f"paciente_id={paciente_id};"
        f"conteudo={conteudo}"
    )

    hash_mensagem = calcular_hash_blake2b(dados_para_assinar)

    assinatura = sign_message(
        carregar_chave_privada(DRA_CARLA, "ed25519"),
        hash_mensagem
    )

    plaintext = (
        f"Tipo: {tipo}\n"
        f"Doente: {paciente_id}\n"
        f"Mensagem: {conteudo}\n"
    )

    # 1. Criar metadados AAD uma única vez
    aad_metadata = criar_metadados_aad(
    sender=sender,
    receiver=receiver,
    message_type=tipo,
    patient_id=paciente_id,
    )

    associated_data = serializar_aad_canonico(aad_metadata)

    # 2. Derivar segredo partilhado e chave simétrica
    shared_secret = derive_shared_secret(
    carregar_chave_privada(DRA_CARLA, "x25519"),
    carregar_chave_publica(ENF_RUI, "x25519")
    )

    chacha_key = derive_chacha20_key(shared_secret)

    # 3. Cifrar com ChaCha20-Poly1305 usando AAD
    nonce, ciphertext = encrypt_message_ChaCha20Poly1305(
    plaintext,
    chacha_key,
    associated_data=associated_data
    )

    # 4. Criar JSON ainda sem assinatura
    message_json = criar_json_mensagem(
    sender=sender,
    receiver=receiver,
    nonce=nonce,
    ciphertext=ciphertext,
    signature=None,
    hash_value=hash_mensagem,
    timestamp=aad_metadata["timestamp"],
    message_type=aad_metadata["message_type"],
    patient_id=aad_metadata["patient_id"],
    algorithm=aad_metadata["algorithm"],
    )

    # 5. Serializar envelope completo de forma canónica
    envelope_canonico = serializar_envelope_assinavel_canonico(message_json)

    # 6. Assinar envelope completo com Ed25519
    private_key_sender = carregar_chave_privada(DRA_CARLA, "ed25519")

    assinatura = sign_message(
    private_key_sender,
    envelope_canonico
    )

    # 7. Inserir assinatura no JSON final
    message_json["signature"] = assinatura.hex()

    # 8. Guardar mensagem
    path = guardar_mensagem_cifrada(message_json)

    print("\n[OK] Mensagem cifrada criada pela Dra. Carla.")
    print("Guardada em:")
    print(path)


def rui_receber_mensagem():
    print("\n--- ENF. RUI: MENSAGENS RECEBIDAS ---")

    mensagens = listar_mensagens(receiver=ENF_RUI)

    if not mensagens:
        print("\n[INFO] Não existem mensagens destinadas ao Enf. Rui.")
        return

    print("\nMensagens disponíveis:")

    for i, path in enumerate(mensagens, start=1):
        try:
            message_json = ler_mensagem_recebida(path.name)

            print(
                f"{i}. "
                f"{message_json.get('timestamp')} | "
                f"De: {message_json.get('sender')} | "
                f"Tipo: {message_json.get('message_type')} | "
                f"Doente: {message_json.get('patient_id')} | "
                f"Ficheiro: {path.name}"
            )

        except Exception:
            print(f"{i}. {path.name} [erro ao ler metadados]")

    try:
        escolha = int(input("\nEscolha a mensagem a abrir: ").strip())

        if escolha < 1 or escolha > len(mensagens):
            print("[ERRO] Opção inválida.")
            return

        path_escolhido = mensagens[escolha - 1]

        message_json = ler_mensagem_recebida(path_escolhido.name)
        campos = extrair_campos_mensagem(message_json)

        if campos["receiver"] != ENF_RUI:
            print("\n[ERRO] Esta mensagem não é destinada ao Enf. Rui.")
            return

        if campos["sender"] != DRA_CARLA:
            print("\n[ERRO DE AUTENTICIDADE]")
            print(f"Remetente declarado inválido: {campos['sender']}")
            print("O sistema só aceita mensagens da Dra. Carla.")
            return

        if campos["signature"] is None:
            print("\n[ERRO DE AUTENTICIDADE]")
            print("A mensagem não contém assinatura digital.")
            print("Mensagem rejeitada.")
            return

        # 1. Reconstruir o envelope canónico recebido
        envelope_canonico = serializar_envelope_assinavel_canonico(message_json)

        # 2. Verificar assinatura Ed25519 sobre o envelope completo
        public_key_sender = carregar_chave_publica(DRA_CARLA, "ed25519")

        assinatura_valida = verify_signature(
        public_key_sender,
        envelope_canonico,
        campos["signature"]
        )

        if not assinatura_valida:
            print("\n[ERRO DE AUTENTICIDADE]")
            print("A assinatura digital do envelope é inválida.")
            print("A mensagem pode ter sido alterada.")
            print("Mensagem rejeitada.")
            return

        shared_secret = derive_shared_secret(
            carregar_chave_privada(ENF_RUI, "x25519"),
            carregar_chave_publica(DRA_CARLA, "x25519")
        )

        chacha_key = derive_chacha20_key(shared_secret)

        aad_metadata = obter_metadados_aad_de_json(message_json)
        associated_data = serializar_aad_canonico(aad_metadata)

        plaintext = decrypt_message_ChaCha20Poly1305(
        campos["nonce"],
        campos["ciphertext"],
        chacha_key,
        associated_data=associated_data
        )

        tipo = message_json.get("message_type")
        paciente_id = message_json.get("patient_id")

        conteudo = extrair_conteudo_clinico(plaintext)

        dados_para_assinar = (
            f"sender={campos['sender']};"
            f"receiver={campos['receiver']};"
            f"tipo={tipo};"
            f"paciente_id={paciente_id};"
            f"conteudo={conteudo}"
        )

        hash_recalculada = calcular_hash_blake2b(dados_para_assinar)

        if hash_recalculada != campos["hash"]:
            print("\n[ERRO DE INTEGRIDADE]")
            print("A hash recalculada não corresponde à hash guardada.")
            print("Mensagem rejeitada.")
            return

   

        print("\n--- RESULTADO DA VERIFICAÇÃO ---")
        print("Remetente:", campos["sender"])
        print("Destinatário:", campos["receiver"])
        print("Tipo:", tipo)
        print("Doente:", paciente_id)
        print("Hash válida?", True)
        print("Assinatura válida?", True)

        print("\n====================================")
        print(" MENSAGEM CLÍNICA DECIFRADA ")
        print("====================================")
        print(plaintext)
        print("====================================")

    except ValueError:
        print("[ERRO] Introduza um número válido.")

    except InvalidTag:
        print("\n[ERRO DE INTEGRIDADE]")
        print("A mensagem cifrada foi alterada, o nonce foi corrompido ou a chave usada não corresponde.")
        print("Mensagem rejeitada pelo ChaCha20-Poly1305.")

    except FileNotFoundError as e:
        print("\n[ERRO]")
        print(e)

    except Exception as e:
        print("\n[ERRO INESPERADO]")
        print(type(e).__name__)
        print(e)



def extrair_conteudo_clinico(plaintext: str) -> str:
    """
    Extrai o conteúdo clínico da mensagem decifrada.
    Espera uma linha no formato:
    Mensagem: conteúdo
    """

    for linha in plaintext.splitlines():
        if linha.startswith("Mensagem: "):
            return linha.replace("Mensagem: ", "", 1)

    return ""

def escolher_tipo_mensagem():
    while True:
        print("\nTipo de mensagem:")
        print("1. Ordem de transferência de doente")
        print("2. Alteração de medicação")
        print("3. Resultado urgente")

        opcao = input("Escolha o tipo: ").strip()

        if opcao in TIPOS_MENSAGEM:
            return TIPOS_MENSAGEM[opcao]

        print("[ERRO] Opção inválida. Escolha 1, 2 ou 3.")


def mostrar_menu():
    print("\n====================================")
    print(f" {NOME_DO_SISTEMA} ")
    print("====================================")
    print("1. Gerir/Gerar chaves")
    print("2. Dra. Carla - Preparar mensagem segura")
    print("3. Enf. Rui - Receber, decifrar e verificar mensagem")
    print("4. Sair")
    print("====================================")


def main():
    while True:
        mostrar_menu()

        opcao = input("Escolha uma opção: ").strip()

        if opcao == "1":
            gerar_chaves_atores()

        elif opcao == "2":
            carla_preparar_mensagem()

        elif opcao == "3":
            rui_receber_mensagem()

        elif opcao == "4":
            print("\nA sair...")
            break

        else:
            print("\n[ERRO] Opção inválida.")


if __name__ == "__main__":
    main()