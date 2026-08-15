# Autenticação de produção — Paxinbot

O código já contém cadastro por e-mail/senha, login com Google, recuperação de senha e passkeys. Antes de publicar, conclua estas configurações no Supabase e no Google Cloud.

## 1. Variáveis na Vercel

Em **Settings → Environment Variables**, adicione para Production, Preview e Development:

- `SUPABASE_URL` — URL base do projeto Supabase, sem `/rest/v1`.
- `SUPABASE_PUBLISHABLE_KEY` — chave `sb_publishable_...`.
- `PUBLIC_SITE_URL` — `https://paxincpa.store`.

Não coloque `service_role`, senha SMTP, segredo do Google ou qualquer token administrativo na Vercel nem no navegador.

## 2. URLs no Supabase

Em **Authentication → URL Configuration**:

- Site URL: `https://paxincpa.store`
- Redirect URLs:
  - `https://paxincpa.store/auth-callback.html`
  - `https://paxincpa.store/auth-callback.html?flow=google`
  - `https://paxincpa.store/auth-callback.html?flow=signup`
  - `https://paxincpa.store/auth-callback.html?flow=recovery`

Mantenha a confirmação de e-mail habilitada e configure SMTP antes de abrir o cadastro ao público.

## 3. Google

1. No Google Cloud Console, crie um OAuth Client do tipo **Web application**.
2. Em Authorized JavaScript origins, adicione `https://paxincpa.store`.
3. Em Authorized redirect URIs, use exatamente o callback mostrado em **Supabase → Authentication → Providers → Google** (normalmente `https://<project-ref>.supabase.co/auth/v1/callback`).
4. Copie o Client ID e o Client Secret para o provedor **Google** no Supabase e habilite-o.

## 4. Passkeys

Passkeys exigem HTTPS, navegador compatível e uma conta cujo e-mail já tenha sido confirmado.

Em **Authentication → Passkeys** no Supabase:

- habilite Passkey authentication;
- Relying party ID: `paxincpa.store`;
- Relying party name: `Paxinbot`;
- Origins permitidas: `https://paxincpa.store`.

O suporte de passkeys do Supabase é experimental; mantenha login por e-mail/senha e Google como alternativas até validar o fluxo em Chrome, Edge e celular.

## Verificação antes do lançamento

1. Criar uma conta e confirmar o e-mail.
2. Fazer login e logout com senha.
3. Entrar com Google em uma conta nova e em uma conta existente.
4. Recuperar senha pelo e-mail.
5. Cadastrar e usar uma passkey em ao menos dois navegadores/dispositivos.
6. Confirmar que `admin.html` continua bloqueado para contas de cliente.
