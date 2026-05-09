from key_manager import (
    gerar_par_rsa,
    carregar_chave_privada,
    carregar_chave_publica,
)

def main():
    #gerar_par_rsa("ruis")
    #gerar_par_rsa("carla")

    #print("Chaves RSA geradas com sucesso.")

    chave_privada_rui = carregar_chave_privada("rui")
    chave_publica_rui = carregar_chave_publica("rui")

    chave_privada_carla = carregar_chave_privada("carla")
    chave_publica_carla = carregar_chave_publica("carla")

    print("Chaves carregadas com sucesso.")
    print(type(chave_privada_rui))
    print(type(chave_publica_rui))
    print(type(chave_privada_carla))
    print(type(chave_publica_carla))


if __name__ == "__main__":
    main()