# Autenticação de produção — Paxinbot

O código já contém cadastro por e-mail/senha, login com Google, recuperação de senha e passkeys. Antes de publicar, conclua estas configurações no Supabase e no Google Cloud.

## 1. Variáveis na Vercel

Em **Settings → Environment Variables**, adicione para Production, Preview e Development:

- `SUPABASE_URL` — URL base do projeto Supabase, sem `/rest/v1`.
- `SUPABASE_PUBLISHABLE_KEY` — chave `sb_publishable_...`.
- `PUBLIC_SITE_URL` — `https://www.paxincpa.store`.

Não coloque `service_role`, senha SMTP, segredo do Google ou qualquer token administrativo na Vercel nem no navegador.

## 2. URLs no Supabase

Em **Authentication → URL Configuration**:

- Site URL: `https://www.paxincpa.store`
- Redirect URLs:
  - `https://www.paxincpa.store/auth-callback.html`
  - `https://www.paxincpa.store/auth-callback.html?flow=google`
  - `https://www.paxincpa.store/auth-callback.html?flow=signup`
  - `https://www.paxincpa.store/auth-callback.html?flow=recovery`

Mantenha a confirmação de e-mail habilitada e configure SMTP antes de abrir o cadastro ao público.

## 3. Google

1. No Google Cloud Console, crie um OAuth Client do tipo **Web application**.
2. Em Authorized JavaScript origins, adicione `https://www.paxincpa.store`.
3. Em Authorized redirect URIs, use exatamente o callback mostrado em **Supabase → Authentication → Providers → Google** (normalmente `https://<project-ref>.supabase.co/auth/v1/callback`).
4. Copie o Client ID e o Client Secret para o provedor **Google** no Supabase e habilite-o.

## 4. Passkeys

Passkeys exigem HTTPS, navegador compatível e uma conta cujo e-mail já tenha sido confirmado.

Em **Authentication → Passkeys** no Supabase:

- habilite Passkey authentication;
- Relying party ID: `paxincpa.store`;
- Relying party name: `Paxinbot`;
- Origins permitidas: `https://www.paxincpa.store`.

O suporte de passkeys do Supabase é experimental; mantenha login por e-mail/senha e Google como alternativas até validar o fluxo em Chrome, Edge e celular.

Se o navegador informar incompatibilidade de domínio, confirme que o site foi aberto em `https://www.paxincpa.store`. O domínio sem `www` deve redirecionar antes de iniciar a passkey. Uma conta precisa cadastrar a passkey em **Minha conta → Segurança** antes de usá-la na tela de login.

## 5. Códigos de verificação por e-mail

A Área do Cliente exige um código de seis dígitos para confirmar novos cadastros e para concluir todo login com e-mail e senha. O Supabase gera, expira e limita as tentativas; o Paxinbot só cria a sessão definitiva depois que o código é validado.

Em **Authentication → Email Templates**:

1. Abra **Confirm sign up** e inclua `{{ .Token }}` no conteúdo. Esse é o código mostrado ao novo cliente.
2. Abra **Magic link or OTP** e inclua `{{ .Token }}` no conteúdo. Esse é o código usado depois da senha.
3. Mantenha os assuntos claros, por exemplo “Seu código de confirmação Paxinbot”.
4. Configure e valide o SMTP antes de abrir o cadastro ao público.

- a etapa posterior à senha usa cookies temporários `HttpOnly`, `SameSite=Strict` e expiração de dez minutos;
- um código de login só é aceito para a mesma conta cuja senha já foi confirmada;
- Google e passkey continuam sendo métodos independentes de autenticação;
- códigos, senhas e tokens não são gravados em logs nem persistidos no navegador;
- o botão de reenvio usa os limites de envio do próprio Supabase.

## Verificação antes do lançamento

1. Criar uma conta, receber o código e confirmar o e-mail.
2. Fazer login com senha, confirmar o segundo código e sair.
3. Entrar com Google em uma conta nova e em uma conta existente.
4. Recuperar senha pelo e-mail.
5. Cadastrar e usar uma passkey em ao menos dois navegadores/dispositivos.
6. Solicitar reenvio, testar código inválido e confirmar que o painel permanece bloqueado.
7. Confirmar que `admin.html` continua bloqueado para contas de cliente.
