from key_manager import (
    gerar_par_ed25519,
    carregar_chave_privada,
    carregar_chave_publica,
    gerar_par_x25519,
)

from hash_manager import calcular_hash_blake2b

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from signature_manager import sign_message, verify_signature


def main():
#-------GERAR CHAVES------------
    gerar_par_ed25519("carla")
    gerar_par_x25519("carla")

    gerar_par_ed25519("rui")
    gerar_par_x25519("rui")

    
    #--------DAR HASH A MENSAGEM-----------integridade

    mensagem = "Olá Carla, esta é uma mensagem segura."

    hash_mensagem = calcular_hash_blake2b(mensagem)

    print("Mensagem:", mensagem)
    print("Hash1:", hash_mensagem)

    mensagemAlterada = "Olá Carla, esta é uma mensagem não é segura."

    hash_mensagem = calcular_hash_blake2b(mensagemAlterada)

    print("Mensagem Alterada:", mensagemAlterada)
    print("Hash2:", hash_mensagem)

    #--------ASSINAR Mensagem----------

    private_key = carregar_chave_privada("rui", "ed25519")

    assinatura = sign_message(private_key,mensagem)

    print("\n\n\nAssinatura:")
    print(assinatura.hex())
    

    public_key = carregar_chave_publica("rui", "ed25519")

    # Verificar com o rui
    valido = verify_signature(public_key,mensagem,assinatura)

    print("Assinatura com chave do rui válida?", valido)

    public_key = carregar_chave_publica("carla", "ed25519")

    # Verificar com a carla
    valido = verify_signature(public_key,mensagem,assinatura)

    print("Assinatura com chave da carla válida?", valido)








    
if __name__ == "__main__":
    main()