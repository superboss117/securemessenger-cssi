from pathlib import Path

from cryptography.hazmat.primitives import hashes

#Gerar hash BLAKE2b da mensagem
def calcular_hash_blake2b(mensagem) :

    mensagem = mensagem.encode("utf-8")

    digest = hashes.Hash(hashes.BLAKE2b(64))
    digest.update(mensagem)
    resultado = digest.finalize()

    return resultado.hex()