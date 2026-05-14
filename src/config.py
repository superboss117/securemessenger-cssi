from pathlib import Path


# =========================================================
# CONFIGURAÇÃO GERAL DO SISTEMA
# =========================================================

NOME_DO_SISTEMA = "Sistema Seguro de Mensagens Hospitalares"

VERSAO_DO_SISTEMA = "1.0"


# =========================================================
# CAMINHOS DAS PASTAS
# =========================================================

BASE_DIR = Path(__file__).resolve().parent.parent

PASTA_DADOS = BASE_DIR / "data"

PASTA_CHAVES = PASTA_DADOS / "keys"

PASTA_MENSAGENS = PASTA_DADOS / "messages"


# =========================================================
# ATORES DO SISTEMA
# =========================================================

DRA_CARLA = "carla"

ENF_RUI = "rui"


# =========================================================
# TIPOS DE MENSAGEM
# =========================================================

TIPOS_MENSAGEM = {
    "1": "transferencia_doente",
    "2": "alteracao_medicacao",
    "3": "resultado_urgente",
}


# =========================================================
# ALGORITMOS UTILIZADOS
# =========================================================

ALGORITMO_HASH = "BLAKE2b"

ALGORITMO_ASSINATURA_DIGITAL = "Ed25519"

ALGORITMO_TROCA_DE_CHAVES = "X25519"

ALGORITMO_DERIVACAO_DE_CHAVES = "HKDF-SHA256"

ALGORITMO_CIFRAGEM = "ChaCha20-Poly1305"

# =========================================================
# ESTRUTURA DO JSON
# =========================================================

CAMPO_REMETENTE = "sender"
CAMPO_DESTINATARIO = "receiver"
CAMPO_TIMESTAMP = "timestamp"
CAMPO_ALGORITMOS = "algorithm"
CAMPO_NONCE = "nonce"
CAMPO_CIPHERTEXT = "ciphertext"
CAMPO_ASSINATURA = "signature"
CAMPO_HASH = "hash"
CAMPO_TIPO_MENSAGEM = "message_type"
CAMPO_ID_DOENTE = "patient_id"
CAMPO_SALT = "salt"