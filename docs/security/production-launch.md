# Publicação final do Paxinbot

Este roteiro substitui a configuração temporária de Preview. Execute na ordem;
não exclua o deployment que ainda atende o domínio oficial.

## 1. Variáveis da Vercel Production

Em **Project > Settings > Environment Variables**, mantenha somente estas no
escopo **Production**:

```dotenv
SUPABASE_URL=https://drkyjgnctbxmupbfarnj.supabase.co
SUPABASE_PUBLISHABLE_KEY=COLE_A_CHAVE_PUBLICAVEL
SUPABASE_SECRET_KEY=COLE_A_CHAVE_SECRETA_DO_BACKEND
PAXINBOT_SESSION_SECRET=COLE_UM_SEGREDO_ALEATORIO_EXCLUSIVO
PUBLIC_SITE_URL=https://www.paxincpa.store
MERCADOPAGO_ACCESS_TOKEN=COLE_O_TOKEN_DE_PRODUCAO
MERCADOPAGO_WEBHOOK_SECRET=COLE_A_ASSINATURA_DO_WEBHOOK
RESEND_API_KEY=COLE_A_CHAVE_DE_ENVIO
RESEND_FROM_EMAIL=Paxinbot <acesso@paxincpa.store>
PAXINBOT_PROTECTED_RELEASE_VERSION=1.0.0
PAXINBOT_PROTECTED_RELEASE_SEQUENCE=9
PAXINBOT_PROTECTED_INTEGRITY_SHA256=COLE_O_HASH_DE_64_CARACTERES
PAXINBOT_PROTECTED_INDEX_SHA256=COLE_O_HASH_DE_64_CARACTERES
PAXINBOT_MODULE_CONTENT_KEY=COLE_A_CHAVE_BASE64URL
PAXINBOT_MODULE_AUTH_PRIVATE_KEY=COLE_A_CHAVE_PRIVADA_BASE64URL
PAXINBOT_MODULE_AUTH_KEY_ID=COLE_O_ID_DA_CHAVE_PUBLICA
```

Depois que o Worker da Etapa 4 estiver publicado, acrescente:

```dotenv
PAXINBOT_ORIGIN_GATE_SECRET=O_MESMO_SEGREDO_GRAVADO_NO_WORKER
```

Todas as chaves devem ser marcadas como **Sensitive**, exceto
`SUPABASE_URL`, `SUPABASE_PUBLISHABLE_KEY`, `PUBLIC_SITE_URL`, versão e sequência.

Exclua do escopo Preview e Production as variáveis antigas de rotação quando
não houver uma rotação em curso:

- `PAXINBOT_ORIGIN_GATE_PREVIOUS_SECRET`;
- `PAXINBOT_ORIGIN_GATE_PREVIOUS_UNTIL`;
- `MERCADOPAGO_WEBHOOK_SECRET_PREVIOUS`;
- `MERCADOPAGO_WEBHOOK_SECRET_PREVIOUS_UNTIL`.

Não crie manualmente `NODE_ENV`, `VERCEL_ENV` ou `VERCEL_URL`.

## 2. Importar o aplicativo sem expô-lo

1. no SQL Editor do Supabase, aplique
   `supabase/migrations/20260901_private_app_download.sql`;
2. abra **Storage > paxinbot-releases** e confirme que o bucket está `Private`;
3. crie a pasta virtual `windows` apenas para organizar o Storage;
4. envie `C:\Users\Guilh\OneDrive\Desktop\PaxinbotSetup.exe` com o nome exato
   `PaxinbotSetup.exe`;
5. confirme o caminho final `windows/PaxinbotSetup.exe`;
6. não torne o bucket público e não crie policy para `anon` ou `authenticated`;
7. não envie o EXE para GitHub, `public/` ou a raiz do projeto Vercel.

O cliente baixa somente `PaxinbotSetup.exe`. A pasta virtual `windows` não é
baixada e não aparece durante a instalação; o próprio setup cria as pastas do
programa no computador.

O arquivo candidato possui:

- tamanho: `101433299` bytes;
- SHA-256: `3139286A02C9C9746881CCACF38F922F1050E15E10A1D1D649F76F206B055387`.

Após a implantação, entre em `/conta`, abra **Downloads** e teste o botão. A
API cria um endereço assinado por 120 segundos e o navegador inicia o download.

## 3. Produção na Vercel e remoção do Preview

1. aplique todas as migrações e faça o upload do instalador;
2. configure as variáveis acima em **Production**;
3. implante a branch `main` e associe `paxincpa.store` e
   `www.paxincpa.store` a esse deployment;
4. teste página pública, cadastro, login, painel, download, checkout, webhook e
   autorização do aplicativo no domínio oficial;
5. somente depois, em **Deployments**, filtre por `Preview`, abra o menu do
   deployment antigo e escolha **Delete**;
6. em **Environment Variables**, remova as cópias com escopo `Preview`;
7. em **Git**, remova a branch temporária apenas se ela não contiver trabalho
   que ainda não chegou à `main`.

Nunca exclua o deployment marcado como `Production` ou aquele que atende os
domínios oficiais.

## 4. Cloudflare: opções a ativar

### DNS

- apex `paxincpa.store` e `www`: **Proxied**;
- registros SPF, DKIM, DMARC e demais registros de e-mail: **DNS only**;
- não criar host público para banco, pooler ou Supabase.

### SSL/TLS

- modo: **Full (strict)**;
- **Always Use HTTPS**: On;
- Minimum TLS: **1.2**;
- TLS 1.3: On;
- HSTS: Off no primeiro lançamento. Depois de sete dias estáveis, começar com
  um mês, sem `includeSubDomains` e sem `Preload`.

### Cache e WAF

- criar a Cache Rule `Paxinbot - dados privados` com `Bypass cache` usando a
  expressão registrada em `cloudflare-activation-guide.md`;
- ativar `Cloudflare Free Managed Ruleset`;
- regra customizada `Block`: `http.request.method in {"TRACE" "CONNECT"}`;
- única regra de rate limit Free: `/api/auth/`, 20 requisições em 10 segundos,
  por IP, bloqueio de 10 segundos;
- manter Bot Fight Mode desligado no lançamento;
- criar notificação por e-mail para `HTTP DDoS Attack Alert`.

### Worker de origem

Depois que todo o site estiver funcionando sem o gate:

1. publicar `cloudflare/origin-gate-worker.mjs` como
   `paxinbot-origin-gate`;
2. criar o Secret `PAXINBOT_ORIGIN_GATE_SECRET` no Worker;
3. adicionar Routes `paxincpa.store/api/*` e
   `www.paxincpa.store/api/*`;
4. gravar o mesmo segredo na Vercel Production e reimplantar;
5. testar o domínio oficial e o rollback antes de excluir o Preview.

O roteiro cumulativo e as expressões completas estão em
`docs/security/cloudflare-activation-guide.md`.
