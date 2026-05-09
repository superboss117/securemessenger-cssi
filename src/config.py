from pathlib import Path


# =========================================
# CAMINHOS DO SISTEMA
# =========================================

BASE_DIR = Path(__file__).resolve().parent.parent

DATA_DIR = BASE_DIR / "data"

KEYS_DIR = DATA_DIR / "keys"

MESSAGES_DIR = DATA_DIR / "messages"


# =========================================
# USERS DO SISTEMA
# =========================================

DRA_CARLA = "carla"

ENF_RUI = "rui"


# =========================================
# CONFIGURAÇÃO CRIPTOGRÁFICA
# =========================================

ALGORITMO_HASH = "BLAKE2b"

ALGORITMO_ASSINATURA = "Ed25519"

ALGORITMO_TROCA_CHAVES = "X25519"

ALGORITMO_KDF = "HKDF-SHA256"

ALGORITMO_CIFRA = "ChaCha20-Poly1305"


# =========================================
# PARÂMETROS CRIPTOGRÁFICOS
# =========================================

TAMANHO_CHAVE_CHACHA20 = 32

TAMANHO_NONCE_CHACHA20 = 12

TAMANHO_DERIVACAO_HKDF = 32

INFO_HKDF = b"securemessenger-hospital"

SALT_HKDF = None


# =========================================
# TIPOS DE MENSAGEM
# =========================================

TIPOS_MENSAGEM = {
    "1": "transferencia_doente",
    "2": "alteracao_medicacao",
    "3": "resultado_urgente",
}


# =========================================
# DEFINIÇÕES DE SEGURANÇA
# =========================================

PERMITIR_REMETENTES_DESCONHECIDOS = False

VALIDAR_ASSINATURAS = True

VALIDAR_HASHES = True

REJEITAR_MENSAGENS_INVALIDAS = True


# =========================================
# DEFINIÇÕES GERAIS DO SISTEMA
# =========================================

NOME_SISTEMA = "Sistema Seguro de Mensagens Hospitalares"

VERSAO_SISTEMA = "1.0"