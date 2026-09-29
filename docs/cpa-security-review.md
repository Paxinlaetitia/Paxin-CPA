# Revisão de segurança — Cash Hunters 1.6.0

Escopo: cliente recuperado, Gerenciar Bots, APIs de licenciamento, painel existente e migração `20260929_cpa_licenses.sql`. Revisão local de 29/09/2026; este documento não atesta implantação em produção.

## Fronteiras de confiança

- O administrador usa a sessão existente do site. Cada RPC administrativa também exige proprietário; esconder a interface não concede nem restringe autorização.
- O servidor guarda HMAC das licenças, peppers versionados, chaves privadas de assinatura e chaves dos módulos por release. O cliente recebe somente a chave pública fixa e, após autorização, a chave daquele motor.
- A identidade do dispositivo combina hash do identificador Windows com prova Ed25519. O vínculo é decidido em transação no banco. DPAPI protege a chave local contra cópia casual para outro usuário; não fornece atestação de hardware.
- A resposta assinada vincula dispositivo, chave pública, nonce, ação, release, escopo e prazo. O cliente desconta o tempo da requisição e usa relógio monotônico. A falha de rede não renova a sessão.

## Pontos revisados

Desafios são consumidos antes da verificação de prova, e nonces são únicos. A renovação troca o token; as operações verificam novamente o hash após adquirir locks. Mudanças administrativas invalidam sessões. Banimento e ativação do mesmo HWID compartilham lock transacional. A migração aplica criação e restrições de acesso atomicamente.

Tabelas têm RLS e acesso direto revogado a anon/authenticated. RPCs do cliente exigem service role; RPCs administrativas exigem proprietário também quando chamadas diretamente. Mutações via navegador exigem origem válida. Há limites por IP, dispositivo e licença, validação de tamanho e limpeza limitada de registros expirados. Logs de segurança usam categorias e identificadores, sem chaves ou conteúdo operacional.

No pacote, manifesto assinado e hashes nativos verificam dependências. O motor cifrado permanece indisponível antes da autorização; um simples retorno booleano de autenticador substituto não fornece a chave de decifragem. Sessões dos dois aplicativos são independentes para evitar disputa pela renovação. Novas operações consultam o servidor; perda de sessão aciona cancelamento e encerramento limitado do processo.

## Limites e condições para entrega

O motor continua executando na máquina do usuário. Um usuário autorizado com controle local pode capturar código e chaves em memória ou modificar o programa. Não há promessa de custo mínimo de engenharia reversa, proteção absoluta, SaaS integral ou atestação de hardware. A versão 1.5.7 já distribuída sem licença não pode ser revogada retroativamente.

O manifesto interno não substitui Authenticode. Nenhum anti-debug agressivo ou alteração de antivírus foi adicionado. HE e enclaves não foram usados: não resolvem a execução e o acesso ao navegador local neste projeto.

A entrega depende de testes do pacote final, instalação e início nativo, backup recuperável, migração e configuração de segredos no servidor, teste HTTPS real e confirmação do mesmo identificador/chave de release. Os recibos ficam na pasta `validation` do build. Testes sintéticos não confirmam comportamento de provedores externos nem operações financeiras reais.
