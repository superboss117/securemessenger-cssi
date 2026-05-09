KANBAN — SecureMessenger (Cenário B)
Criptografia e Segurança de Sistemas Informáticos
Mestrado em Engenharia Informática — UTAD

==================================================
K1 — Criar repositório e estrutura base          
==================================================

Objetivo:
Criar a estrutura inicial do projeto SecureMessenger.

O que fazer:
- Criar o repositório GitHub.
- Criar as pastas:
  - src/
  - data/
  - data/keys/
  - data/messages/
  - data/messages/inbox/
  - data/messages/outbox/
  - relatorio/
- Criar os ficheiros:
  - README.md
  - requirements.txt
  - src/main.py
  - src/config.py
  - src/messenger.py

Critério de aceitação:
- O projeto abre corretamente no Neovim.
- O comando tree mostra a estrutura organizada.
- O Git reconhece todos os ficheiros.

==================================================
K2 — Configurar ambiente Python                     ✅ Feito
==================================================

Objetivo:
Preparar o ambiente Python isolado do projeto.

O que fazer:
- Criar ambiente virtual:
  python -m venv .venv
- Ativar:
  source .venv/bin/activate
- Instalar cryptography:
  pip install cryptography
- Gerar requirements.txt:
  pip freeze > requirements.txt

Critério de aceitação:
- python funciona dentro da .venv
- cryptography aparece em pip list
- requirements.txt foi criado

==================================================
K3 — Configurar constantes do projeto           ✅ Feito
==================================================

Objetivo:
Centralizar caminhos e nomes importantes.

O que fazer:
- Criar constantes em config.py:
  - BASE_DIR
  - DATA_DIR
  - KEYS_DIR
  - MESSAGES_DIR
  - INBOX_DIR
  - OUTBOX_DIR
  - nomes dos utilizadores
  - nomes dos ficheiros PEM

Critério de aceitação:
- Nenhum caminho importante fica hardcoded no resto do código.

==================================================
K4 — Criar inicialização automática das pastas     
==================================================

Objetivo:
Garantir que o programa cria automaticamente as pastas necessárias.

O que fazer:
- Criar função:
  ensure_directories()
- Verificar se cada pasta existe.
- Criar automaticamente caso não exista.

Critério de aceitação:
- Apagar data/ e correr o programa recria tudo automaticamente.

==================================================
K5 — Implementar geração de chaves RSA              ✅ Feito
==================================================

Objetivo:
Gerar pares de chaves para Carla e Rui.

O que fazer:
- Criar função generate_rsa_keypair()
- Gerar:
  - private_key.pem
  - public_key.pem
- Guardar em formato PEM.

Critério de aceitação:
- Os ficheiros PEM aparecem corretamente nas pastas.

==================================================
K6 — Implementar carregamento de chaves            ✅ Feito
==================================================

Objetivo:
Carregar chaves PEM para memória.

O que fazer:
- Criar:
  load_private_key()
  load_public_key()
- Ler ficheiros PEM.
- Retornar objetos de chave RSA.

Critério de aceitação:
- As chaves carregam sem erro.

==================================================
K7 — Implementar proteção contra overwrite
==================================================

Objetivo:
Evitar apagar chaves existentes acidentalmente.

O que fazer:
- Verificar se os ficheiros PEM já existem.
- Pedir confirmação antes de regenerar.

Critério de aceitação:
- O utilizador recebe aviso antes de substituir chaves.

==================================================
K8 — Implementar hashing BLAKE2b
==================================================

Objetivo:
Garantir integridade da mensagem.

O que fazer:
- Criar:
  hash_message()
- Usar SBLAKE2b
- Gerar hash da mensagem e metadados.

Critério de aceitação:
- Alterar um caractere altera completamente o hash.

==================================================
K9 — Implementar assinatura digital RSA-PSS
==================================================

Objetivo:
Garantir autenticidade da mensagem.

O que fazer:
- Criar:
  sign_message()
  verify_signature()
- Assinar com chave privada da Carla.
- Verificar com chave pública da Carla.

Critério de aceitação:
- Mensagem legítima passa verificação.
- Mensagem adulterada falha.

==================================================
K10 — Implementar cifra AES-GCM
==================================================

Objetivo:
Garantir confidencialidade da mensagem.

O que fazer:
- Criar:
  encrypt_message()
  decrypt_message()
- Gerar chave AES aleatória.
- Gerar nonce aleatório.
- Usar AES-GCM.

Critério de aceitação:
- Só quem possui a chave AES consegue decifrar.
- Alterações no ciphertext são detetadas.

==================================================
K11 — Implementar RSA-OAEP para chave AES
==================================================

Objetivo:
Transportar a chave AES de forma segura.

O que fazer:
- Cifrar chave AES com chave pública do Rui.
- Decifrar com chave privada do Rui.

Critério de aceitação:
- Apenas o Rui consegue recuperar a chave AES.

==================================================
K12 — Definir formato JSON da mensagem segura
==================================================

Objetivo:
Estruturar o ficheiro trocado na rede.

O que fazer:
- Criar JSON com:
  - sender
  - receiver
  - timestamp
  - encrypted_key
  - nonce
  - ciphertext
  - signature

Critério de aceitação:
- O JSON é legível e contém todos os dados necessários.

==================================================
K13 — Implementar envio de mensagem segura
==================================================

Objetivo:
Permitir à Carla preparar mensagens seguras.

O que fazer:
- Ler mensagem em claro.
- Calcular hash.
- Assinar.
- Cifrar conteúdo.
- Cifrar chave AES.
- Guardar JSON em outbox.

Critério de aceitação:
- O ficheiro seguro aparece na pasta.

==================================================
K14 — Implementar receção de mensagem
==================================================

Objetivo:
Permitir ao Rui receber mensagens.

O que fazer:
- Ler JSON.
- Recuperar chave AES.
- Decifrar conteúdo.
- Recalcular hash.
- Verificar assinatura.

Critério de aceitação:
- O Rui consegue ler mensagem válida.

==================================================
K15 — Guardar mensagens recebidas
==================================================

Objetivo:
Arquivar mensagens válidas.

O que fazer:
- Criar ficheiro TXT da mensagem recebida.
- Guardar em inbox.

Critério de aceitação:
- Mensagens válidas ficam guardadas localmente.

==================================================
K16 — Implementar deteção de adulteração
==================================================

Objetivo:
Detetar alterações maliciosas.

O que fazer:
- Alterar manualmente:
  - ciphertext
  - assinatura
  - hash
- Verificar comportamento do sistema.

Critério de aceitação:
- Mensagem adulterada é rejeitada.

==================================================
K17 — Criar menu principal
==================================================

Objetivo:
Organizar todas as funcionalidades.

O que fazer:
- Criar menu:
  1. Gestão de chaves
  2. Carla
  3. Rui
  4. Testes
  0. Sair

Critério de aceitação:
- O utilizador consegue navegar sem erros.

==================================================
K18 — Criar menu da Carla
==================================================

Objetivo:
Separar ações da Dra. Carla.

O que fazer:
- Escrever mensagem manualmente.
- Criar mensagem a partir de TXT.
- Listar mensagens enviadas.

Critério de aceitação:
- Carla consegue enviar mensagens pelo menu.

==================================================
K19 — Criar menu do Rui
==================================================

Objetivo:
Separar ações do Rui.

O que fazer:
- Listar mensagens disponíveis.
- Verificar mensagens.
- Guardar mensagens válidas.

Critério de aceitação:
- Rui consegue receber mensagens pelo menu.

==================================================
K20 — Implementar tratamento de erros
==================================================

Objetivo:
Evitar crashes do programa.

O que fazer:
- Tratar:
  - ficheiros inexistentes
  - JSON inválido
  - assinatura inválida
  - opção inválida
  - chaves em falta

Critério de aceitação:
- O programa nunca termina abruptamente.

==================================================
K21 — Criar dados de teste
==================================================

Objetivo:
Preparar demonstração completa.

O que fazer:
- Gerar:
  - chaves
  - mensagem válida
  - mensagem adulterada
  - TXT original

Critério de aceitação:
- O professor consegue testar sem repetir todo o fluxo.

==================================================
K22 — Criar README
==================================================

Objetivo:
Documentar utilização do projeto.

O que fazer:
- Explicar:
  - instalação
  - execução
  - estrutura
  - menus

Critério de aceitação:
- Uma pessoa externa consegue correr o projeto.

==================================================
K23 — Criar diagrama de arquitetura
==================================================

Objetivo:
Visualizar o fluxo criptográfico.

O que fazer:
- Mostrar:
  Carla
  assinatura
  hash
  AES-GCM
  RSA-OAEP
  pasta partilhada
  Rui

Critério de aceitação:
- O diagrama explica claramente o sistema.

==================================================
K24 — Escrever secção 1 do relatório
==================================================

Objetivo:
Explicar objetivo do sistema.

O que fazer:
- Descrever:
  - o que o sistema faz
  - o que não faz

Critério de aceitação:
- 5 a 8 linhas em português.

==================================================
K25 — Escrever secção 2 do relatório
==================================================

Objetivo:
Descrever arquitetura.

O que fazer:
- Inserir diagrama.
- Explicar mecanismos criptográficos.

Critério de aceitação:
- O fluxo fica claro para o avaliador.

==================================================
K26 — Escrever decisões técnicas
==================================================

Objetivo:
Justificar escolhas criptográficas.

O que fazer:
- Explicar:
  - RSA-OAEP
  - AES-GCM
  - RSA-PSS
  - SHA-256

Critério de aceitação:
- Cada decisão inclui alternativa rejeitada e risco.

==================================================
K27 — Escrever vulnerabilidades e mitigações
==================================================

Objetivo:
Mostrar análise crítica de segurança.

O que fazer:
- Explicar:
  - adulteração
  - replay attacks
  - troca de chaves públicas
  - perda de chave privada

Critério de aceitação:
- Pelo menos 2 vulnerabilidades detalhadas.

==================================================
K28 — Comparar assinar/cifrar
==================================================

Objetivo:
Justificar ordem criptográfica usada.

O que fazer:
- Comparar:
  - assinar depois cifrar
  - cifrar depois assinar

Critério de aceitação:
- A escolha do sistema está justificada.

==================================================
K29 — Escrever limitações e melhorias
==================================================

Objetivo:
Mostrar consciência técnica.

O que fazer:
- Listar:
  - limitações reais
  - melhorias futuras

Critério de aceitação:
- Não usar “falta de tempo”.

==================================================
K30 — Revisão final
==================================================

Objetivo:
Confirmar cumprimento da grelha.

O que fazer:
- Verificar todos os critérios do enunciado.

Critério de aceitação:
- Nada importante ficou em falta.

==================================================
K31 — Criar ZIP final
==================================================

Objetivo:
Preparar entrega.

O que fazer:
- Organizar ficheiros.
- Confirmar:
  - relatorio.pdf
  - src/
  - dados de teste

Critério de aceitação:
- ZIP pronto para upload na plataforma.