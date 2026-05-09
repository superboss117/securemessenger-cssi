from key_manager import (
    gerar_par_ed25519,
    carregar_chave_privada,
    carregar_chave_publica,
    gerar_par_x25519,
)

from hash_manager import calcular_hash_blake2b

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from signature_manager import sign_message, verify_signature

from x25519_manager import derive_chacha20_key,derive_shared_secret


def main():
#-------GERAR CHAVES------------
    gerar_par_ed25519("carla")
    gerar_par_x25519("carla")

    gerar_par_ed25519("rui")
    gerar_par_x25519("rui")

    
    #--------DAR HASH A MENSAGEM BLAKE2b-----------integridade

    mensagem = "Olá Carla, esta é uma mensagem segura."

    hash_mensagem = calcular_hash_blake2b(mensagem)

    print("Mensagem:", mensagem)
    print("Hash1:", hash_mensagem)

    mensagemAlterada = "Olá Carla, esta é uma mensagem não é segura."

    hash_mensagem = calcular_hash_blake2b(mensagemAlterada)

    print("Mensagem Alterada:", mensagemAlterada)
    print("Hash2:", hash_mensagem)

    #--------ASSINAR Mensagem Ed25519---------- autenticidade

    private_key = carregar_chave_privada("rui", "ed25519")

    assinatura = sign_message(private_key,mensagem)

    print("\nAssinatura:")
    print(assinatura.hex())
    

    public_key = carregar_chave_publica("rui", "ed25519")

    # Verificar com o rui
    valido = verify_signature(public_key,mensagem,assinatura)

    print("Assinatura com chave do rui válida?", valido)

    public_key = carregar_chave_publica("carla", "ed25519")

    # Verificar com a carla
    valido = verify_signature(public_key,mensagem,assinatura)

    print("Assinatura com chave da carla válida?", valido)



    #------Gerar par de chave para encriptação simetrica X25519 -> HKDF 

    # Rui calcula o segredo usando:
    # privada do Rui + pública da Carla
    rui_shared_secret = derive_shared_secret( carregar_chave_privada("rui", "x25519"),carregar_chave_publica("carla", "x25519"))
    print("\nsegredo drivado do rui com X25519:",rui_shared_secret)

    # Carla calcula o segredo usando:
    # privada da Carla + pública do Rui
    carla_shared_secret = derive_shared_secret(carregar_chave_privada("carla", "x25519"),carregar_chave_publica("rui", "x25519"))
    print("segredo drivado da carla com X25519:",carla_shared_secret)


    print(rui_shared_secret == carla_shared_secret)  # True

    # Ambos derivam a mesma chave ChaCha20
    rui_chacha_key = derive_chacha20_key(rui_shared_secret)
    carla_chacha_key = derive_chacha20_key(carla_shared_secret)

    print("Chave do chacha20 do rui e carla com com HKDF:", rui_chacha_key)


    print(rui_chacha_key == carla_chacha_key)  # True




    #--------------> encriptar mensagem  -> ChaCha20-Poly1305



    
    
if __name__ == "__main__":
    main()