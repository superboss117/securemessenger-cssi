import os
import getpass

from cryptography.exceptions import InvalidTag

from config import (
    NOME_DO_SISTEMA,
    DRA_CARLA,
    ENF_RUI,
    TIPOS_MENSAGEM,
)

from key_manager import (
    gerar_par_ed25519,
    gerar_par_x25519,
    carregar_chave_privada,
    carregar_chave_publica,
)

from x25519_manager import (
    derive_shared_secret,
    derive_chacha20_key,
)

from crypto_manager import (
    encrypt_message_ChaCha20Poly1305,
    decrypt_message_ChaCha20Poly1305,
)

from signature_manager import (
    sign_message,
    verify_signature,
)

from hash_manager import calcular_hash_blake2b

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


# =========================================================
# PASSWORDS
# =========================================================

def pedir_password_chaves(ator: str, confirmar: bool = False) -> str:
    """
    Pede a password das chaves privadas de um ator.

    Args:
        ator: nome do ator, por exemplo "carla" ou "rui".
        confirmar: se True, pede confirmação da password.

    Returns:
        Password em string.
    """

    while True:
        password = getpass.getpass(
            f"Password das chaves privadas de {ator}: "
        )

        if not password:
            print("[ERRO] A password não pode estar vazia.")
            continue

        if len(password.encode("utf-8")) < 8:
            print("[ERRO] A password deve ter pelo menos 8 caracteres.")
            continue

        if confirmar:
            password_confirmacao = getpass.getpass(
                f"Confirmar password das chaves privadas de {ator}: "
            )

            if password != password_confirmacao:
                print("[ERRO] As passwords não coincidem.")
                continue

        return password


# =========================================================
# GESTÃO DE CHAVES
# =========================================================

def gerar_chaves_carla():
    """
    Gera ou gere as chaves da Dra. Carla.
    """

    print("\n--- DRA. CARLA: GERAR/GERIR CHAVES ---")

    try:
        password = pedir_password_chaves(DRA_CARLA, confirmar=True)

        gerar_par_ed25519(DRA_CARLA, password=password)
        gerar_par_x25519(DRA_CARLA, password=password)

        print("\n[OK] Chaves da Dra. Carla geridas com sucesso.")

    except Exception as e:
        print("\n[ERRO AO GERAR CHAVES DA DRA. CARLA]")
        print(type(e).__name__)
        print(e)


def gerar_chaves_rui():
    """
    Gera ou gere as chaves do Enf. Rui.
    """

    print("\n--- ENF. RUI: GERAR/GERIR CHAVES ---")

    try:
        password = pedir_password_chaves(ENF_RUI, confirmar=True)

        gerar_par_x25519(ENF_RUI, password=password)

        print("\n[OK] Chaves do Enf. Rui geridas com sucesso.")

    except Exception as e:
        print("\n[ERRO AO GERAR CHAVES DO ENF. RUI]")
        print(type(e).__name__)
        print(e)


# =========================================================
# DRA. CARLA - PREPARAR MENSAGEM
# =========================================================

def carla_preparar_mensagem():
    """
    Fluxo da Dra. Carla:
    - escolhe tipo de mensagem;
    - introduz paciente e conteúdo clínico;
    - pede password da Carla;
    - carrega chaves privadas da Carla;
    - deriva chave simétrica com X25519 + HKDF + salt;
    - cifra com ChaCha20-Poly1305 + AAD;
    - assina envelope completo com Ed25519;
    - guarda JSON.
    """

    print("\n--- DRA. CARLA: PREPARAR MENSAGEM SEGURA ---")

    try:
        tipo = escolher_tipo_mensagem()

        paciente_id = input("ID do doente: ").strip()

        if not paciente_id:
            print("[ERRO] O ID do doente não pode estar vazio.")
            return

        conteudo = input("Conteúdo clínico da mensagem: ").strip()

        if not conteudo:
            print("[ERRO] O conteúdo da mensagem não pode estar vazio.")
            return

        sender = DRA_CARLA
        receiver = ENF_RUI

        plaintext = (
            f"Tipo: {tipo}\n"
            f"Paciente ID: {paciente_id}\n"
            f"Mensagem: {conteudo}"
        )

        hash_mensagem = calcular_hash_blake2b(plaintext)

        password_carla = pedir_password_chaves(DRA_CARLA)

        # 1. Criar metadados AAD
        aad_metadata = criar_metadados_aad(
            sender=sender,
            receiver=receiver,
            message_type=tipo,
            patient_id=paciente_id,
        )

        associated_data = serializar_aad_canonico(aad_metadata)

        # 2. Calcular segredo partilhado X25519
        shared_secret = derive_shared_secret(
            carregar_chave_privada(
                DRA_CARLA,
                "x25519",
                password=password_carla,
            ),
            carregar_chave_publica(ENF_RUI, "x25519"),
        )

        # 3. Gerar salt aleatório por mensagem
        salt = os.urandom(16)

        # 4. Derivar chave ChaCha20-Poly1305 com HKDF + salt.
        # A função derive_chacha20_key já aceita salt e deriva 32 bytes [1].
        chacha_key = derive_chacha20_key(
            shared_secret,
            salt=salt,
        )

        # 5. Cifrar com ChaCha20-Poly1305 usando AAD
        nonce, ciphertext = encrypt_message_ChaCha20Poly1305(
            plaintext,
            chacha_key,
            associated_data=associated_data,
        )

        # 6. Criar JSON ainda sem assinatura
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
            salt=salt,
        )

        # 7. Criar envelope canónico para assinatura
        envelope_canonico = serializar_envelope_assinavel_canonico(
            message_json
        )

        # 8. Assinar envelope completo com Ed25519.
        # O signature_manager assina a string codificada em UTF-8 [6].
        private_key_sender = carregar_chave_privada(
            DRA_CARLA,
            "ed25519",
            password=password_carla,
        )

        assinatura = sign_message(
            private_key_sender,
            envelope_canonico,
        )

        # 9. Inserir assinatura no JSON final
        message_json["signature"] = assinatura.hex()

        # 10. Guardar mensagem
        path = guardar_mensagem_cifrada(message_json)

        print("\n[OK] Mensagem cifrada criada pela Dra. Carla.")
        print("Guardada em:")
        print(path)

    except FileNotFoundError as e:
        print("\n[ERRO]")
        print(e)

    except ValueError as e:
        print("\n[ERRO]")
        print("Password incorreta, chave inválida ou dados inválidos.")
        print(e)

    except TypeError as e:
        print("\n[ERRO]")
        print("Erro ao carregar chave privada.")
        print("Confirma se as chaves foram geradas com password.")
        print(e)

    except Exception as e:
        print("\n[ERRO INESPERADO]")
        print(type(e).__name__)
        print(e)


# =========================================================
# ENF. RUI - RECEBER MENSAGEM
# =========================================================

def rui_receber_mensagem():
    """
    Fluxo do Enf. Rui:
    - lista mensagens destinadas ao Rui;
    - lê JSON;
    - valida sender/receiver;
    - verifica assinatura do envelope completo;
    - pede password do Rui;
    - carrega chave privada X25519 do Rui;
    - deriva chave com X25519 + HKDF + salt;
    - reconstrói AAD;
    - decifra;
    - valida hash BLAKE2b.
    """

    print("\n--- ENF. RUI: MENSAGENS RECEBIDAS ---")

    try:
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
                print(f"{i}. [ERRO AO LER] {path.name}")

        try:
            escolha = int(input("\nEscolha a mensagem a abrir: ").strip())
        except ValueError:
            print("[ERRO] Introduza um número.")
            return

        if escolha < 1 or escolha > len(mensagens):
            print("[ERRO] Opção inválida.")
            return

        path = mensagens[escolha - 1]
        message_json = ler_mensagem_recebida(path.name)

        campos = extrair_campos_mensagem(message_json)

        # 1. Validar destinatário
        if campos["receiver"] != ENF_RUI:
            print("\n[ERRO] Esta mensagem não é destinada ao Enf. Rui.")
            return

        # 2. Validar remetente declarado
        if campos["sender"] != DRA_CARLA:
            print("\n[ERRO DE AUTENTICIDADE]")
            print(f"Remetente declarado inválido: {campos['sender']}")
            print("O sistema só aceita mensagens da Dra. Carla.")
            return

        # 3. Validar existência de assinatura
        if campos.get("signature") is None:
            print("\n[ERRO DE AUTENTICIDADE]")
            print("A mensagem não contém assinatura digital.")
            print("Mensagem rejeitada.")
            return

        # 4. Validar existência de salt
        if campos.get("salt") is None:
            print("\n[ERRO CRIPTOGRÁFICO]")
            print("A mensagem não contém salt para o HKDF.")
            print("Mensagem antiga ou inválida.")
            print("Mensagem rejeitada.")
            return

        # 5. Verificar assinatura do envelope completo antes de decifrar.
        # A verificação usa a chave pública Ed25519 da Carla [6].
        envelope_canonico = serializar_envelope_assinavel_canonico(
            message_json
        )

        public_key_sender = carregar_chave_publica(
            DRA_CARLA,
            "ed25519",
        )

        assinatura_valida = verify_signature(
            public_key_sender,
            envelope_canonico,
            campos["signature"],
        )

        if not assinatura_valida:
            print("\n[ERRO DE AUTENTICIDADE]")
            print("A assinatura digital do envelope é inválida.")
            print("A mensagem pode ter sido alterada ou falsificada.")
            print("Mensagem rejeitada.")
            return

        # 6. Só agora pedir password do Rui para decifrar
        password_rui = pedir_password_chaves(ENF_RUI)

        # 7. Calcular segredo partilhado X25519
        shared_secret = derive_shared_secret(
            carregar_chave_privada(
                ENF_RUI,
                "x25519",
                password=password_rui,
            ),
            carregar_chave_publica(DRA_CARLA, "x25519"),
        )

        # 8. Derivar chave com o salt guardado no JSON
        chacha_key = derive_chacha20_key(
            shared_secret,
            salt=campos["salt"],
        )

        # 9. Reconstruir AAD a partir do JSON
        aad_metadata = obter_metadados_aad_de_json(message_json)
        associated_data = serializar_aad_canonico(aad_metadata)

        # 10. Decifrar
        plaintext = decrypt_message_ChaCha20Poly1305(
            campos["nonce"],
            campos["ciphertext"],
            chacha_key,
            associated_data=associated_data,
        )

        # 11. Validar hash BLAKE2b
        hash_recalculada = calcular_hash_blake2b(plaintext)

        if hash_recalculada != campos.get("hash"):
            print("\n[ERRO DE INTEGRIDADE]")
            print("A hash BLAKE2b da mensagem não corresponde.")
            print("Mensagem rejeitada.")
            return

        tipo = message_json.get("message_type")
        paciente_id = message_json.get("patient_id")
        conteudo = extrair_conteudo_clinico(plaintext)

        print("\n[OK] Mensagem autenticada, decifrada e validada.")
        print("------------------------------------")
        print(f"Remetente: {campos['sender']}")
        print(f"Destinatário: {campos['receiver']}")
        print(f"Timestamp: {campos['timestamp']}")
        print(f"Tipo: {tipo}")
        print(f"ID do doente: {paciente_id}")
        print("------------------------------------")
        print("Conteúdo clínico:")
        print(conteudo)
        print("------------------------------------")

    except InvalidTag:
        print("\n[ERRO DE INTEGRIDADE]")
        print(
            "A mensagem cifrada foi alterada, o nonce foi corrompido, "
            "o AAD não corresponde ou a chave usada não corresponde."
        )
        print("Mensagem rejeitada pelo ChaCha20-Poly1305.")

    except FileNotFoundError as e:
        print("\n[ERRO]")
        print(e)

    except ValueError as e:
        print("\n[ERRO]")
        print("Password incorreta, chave inválida ou mensagem inválida.")
        print(e)

    except TypeError as e:
        print("\n[ERRO]")
        print("Erro ao carregar chave privada.")
        print("Confirma se as chaves foram geradas com password.")
        print(e)

    except Exception as e:
        print("\n[ERRO INESPERADO]")
        print(type(e).__name__)
        print(e)


# =========================================================
# FUNÇÕES AUXILIARES
# =========================================================

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
    """
    Mostra menu de tipos de mensagem e devolve o tipo escolhido.
    """

    while True:
        print("\nTipo de mensagem:")
        print("1. Ordem de transferência de doente")
        print("2. Alteração de medicação")
        print("3. Resultado urgente")

        opcao = input("Escolha o tipo: ").strip()

        if opcao in TIPOS_MENSAGEM:
            return TIPOS_MENSAGEM[opcao]

        print("[ERRO] Opção inválida. Escolha 1, 2 ou 3.")


# =========================================================
# MENUS
# =========================================================

def menu_carla():
    """
    Menu específico da Dra. Carla.
    """

    while True:
        print("\n====================================")
        print("Menu da Dra. Carla")
        print("====================================")
        print("1. Gerar/Gerir chaves da Dra. Carla")
        print("2. Preparar mensagem segura")
        print("3. Voltar")
        print("====================================")

        opcao = input("Escolha uma opção: ").strip()

        if opcao == "1":
            gerar_chaves_carla()

        elif opcao == "2":
            carla_preparar_mensagem()

        elif opcao == "3":
            break

        else:
            print("\n[ERRO] Opção inválida.")


def menu_rui():
    """
    Menu específico do Enf. Rui.
    """

    while True:
        print("\n====================================")
        print("Menu do Enf. Rui")
        print("====================================")
        print("1. Gerar/Gerir chaves do Enf. Rui")
        print("2. Receber, decifrar e verificar mensagem")
        print("3. Voltar")
        print("====================================")

        opcao = input("Escolha uma opção: ").strip()

        if opcao == "1":
            gerar_chaves_rui()

        elif opcao == "2":
            rui_receber_mensagem()

        elif opcao == "3":
            break

        else:
            print("\n[ERRO] Opção inválida.")


def mostrar_menu_principal():
    """
    Menu principal do sistema.
    """

    print("\n====================================")
    print(f" {NOME_DO_SISTEMA} ")
    print("====================================")
    print("1. Dra. Carla")
    print("2. Enf. Rui")
    print("3. Sair")
    print("====================================")


def main():
    """
    Entrada principal do programa.
    """

    while True:
        mostrar_menu_principal()

        opcao = input("Escolha uma opção: ").strip()

        if opcao == "1":
            menu_carla()

        elif opcao == "2":
            menu_rui()

        elif opcao == "3":
            print("\nA sair...")
            break

        else:
            print("\n[ERRO] Opção inválida.")


if __name__ == "__main__":
    main()