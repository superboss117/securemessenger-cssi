# SecureMessenger — CSSI UTAD 2026

Sistema de mensagens seguras desenvolvido para a unidade curricular de **Criptografia e Segurança de Sistemas Informáticos** do **Mestrado em Engenharia Informática — UTAD**.

## Cenário

Este projeto implementa o **Cenário B — SecureMessenger**.

O sistema permite a troca segura de mensagens clínicas entre:

- **Dra. Carla** — médica responsável pelo envio das mensagens
- **Enf. Rui** — destinatário autorizado das mensagens

As mensagens são trocadas através de uma pasta partilhada considerada **não segura**.

O objetivo é garantir:

- **Confidencialidade** — apenas o destinatário consegue ler a mensagem
- **Integridade** — qualquer alteração da mensagem é detetada
- **Autenticidade** — o destinatário consegue verificar quem enviou a mensagem
- **Não repúdio** — o remetente não pode negar o envio da mensagem assinada

---

# Tecnologias Utilizadas

- Python 3.11+
- Package `cryptography`

---

# Estrutura do Projeto

```text
securemessenger-cssi/
├── README.md
├── requirements.txt
├── src/
│   ├── main.py
│   ├── crypto_utils.py
│   ├── key_manager.py
│   ├── messenger.py
│   └── file_utils.py
├── data/
│   ├── keys/
│   │   ├── carla/
│   │   └── rui/
│   ├── messages/
│   │   ├── outbox/
│   │   └── inbox/
│   └── test_files/
└── relatorio/
    └── relatorio.pdf
```

---

# Arquitetura Criptográfica

O sistema utiliza uma arquitetura híbrida:

| Função | Tecnologia |
|---|---|
| Cifra da mensagem | AES-256-GCM |
| Troca segura da chave AES | RSA-OAEP |
| Assinatura digital | RSA-PSS + SHA-256 |
| Hashing | SHA-256 |
| Geração de chaves | RSA 4096 bits |

Fluxo geral:

1. Carla escreve a mensagem
2. A mensagem é assinada digitalmente
3. É gerada uma chave AES aleatória
4. A mensagem assinada é cifrada com AES-GCM
5. A chave AES é cifrada com a chave pública do Rui
6. O pacote final é armazenado na pasta partilhada

No lado do Rui:

1. A chave AES é recuperada usando a chave privada
2. A mensagem é decifrada
3. A assinatura digital é verificada
4. O sistema valida autenticidade e integridade

---

# Instalação

## Clonar o repositório

```bash
git clone https://github.com/superboss117/securemessenger-cssi.git
cd securemessenger-cssi
```

## Criar ambiente virtual

```bash
python -m venv .venv
source .venv/bin/activate
```

## Instalar dependências

```bash
pip install -r requirements.txt
```

---

# Execução

```bash
python src/main.py
```

---

# Funcionalidades

- Geração automática de pares de chaves RSA
- Envio seguro de mensagens
- Assinatura digital
- Verificação de autenticidade
- Deteção de adulteração
- Gestão automática de pastas
- Exportação/importação de mensagens
- Tratamento de erros

---

# Segurança

## Medidas Implementadas

- AES em modo autenticado (GCM)
- RSA-OAEP para encapsulamento de chave
- RSA-PSS para assinatura digital
- Chaves nunca hardcoded
- ECB completamente evitado
- Integridade validada antes da aceitação da mensagem

## Limitações Conhecidas

- Não existe PKI real nem certificados X.509
- As chaves privadas são armazenadas localmente
- Não existe proteção contra eliminação de mensagens por terceiros

---

# Dados de Teste

O projeto inclui:

- Chaves de teste
- Mensagens cifradas
- Exemplos de verificação
- Estrutura de diretórios automática

Os dados são suficientes para testar todas as funcionalidades sem repetir o fluxo completo.

---

# Autores

Projeto desenvolvido para fins académicos no âmbito da UC:

**Criptografia e Segurança de Sistemas Informáticos**  
Mestrado em Engenharia Informática — UTAD  
2025/2026