# Segurança do site — pacote 3

O Pacote 3 protege fluxos comerciais e de autenticação contra força bruta,
automação abusiva e consumo excessivo de recursos.

## Implementado na origem

- contador distribuído e atômico no Supabase;
- retenção automática dos contadores antigos, com índice próprio para limpeza;
- identificadores de IP, conta e e-mail convertidos em HMAC antes de chegar ao
  banco;
- respostas fail-closed quando a proteção não estiver disponível;
- respostas `429` com `Retry-After`, `RateLimit` e `RateLimit-Policy`;
- limites separados para login, cadastro, recuperação, códigos por e-mail,
  callback OAuth, troca de senha, conta, suporte, promoções, checkout e owner;
- limites de leitura compatíveis com o polling legítimo do checkout e do painel;
- regra de rajada preparada para o único rate limit do Cloudflare Free.

## Ativação futura

1. aplicar `supabase/migrations/20260829_api_abuse_limits.sql`;
2. publicar a branch de teste com as variáveis corretas;
3. validar login, cadastro, checkout, painel e aplicativo;
4. somente na promoção final, ativar a regra descrita em
   `docs/security/cloudflare-package-3.md`.

Nenhuma configuração da Cloudflare ou implantação da Vercel é alterada por este
commit.
