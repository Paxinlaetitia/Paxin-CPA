# Segurança do site — pacote 5

O Pacote 5 adiciona observabilidade defensiva entre Cloudflare, Vercel,
Supabase, autenticação e Mercado Pago. Nada é publicado ou ativado
automaticamente.

## Implementado

- identificador UUID por requisição devolvido em `X-Paxinbot-Request-Id`;
- eventos persistentes com tipos, severidades e detalhes enumerados;
- IP, e-mail, identificador do pagamento e Cloudflare Ray transformados em
  HMAC antes de qualquer persistência;
- ausência deliberada de senha, token, cookie, corpo, query string, User-Agent
  e conteúdo digitado nos eventos;
- trilha para rate limit, CSRF, autenticação recusada, sessão inválida,
  alteração de senha, acesso administrativo negado e falhas de pagamento;
- auditoria do owner combinando eventos comerciais e de segurança;
- retenção de 90 dias com limpeza probabilística no próprio RPC;
- falha de telemetria não interrompe login, checkout ou webhook, mas gera um
  diagnóstico sanitizado e correlacionável nos logs da Vercel.

## Migração necessária

Aplicar no ambiente de teste, depois das anteriores:

`supabase/migrations/20260830_site_security_observability.sql`

A tabela possui RLS, não concede leitura ou escrita a `anon` ou
`authenticated`, e aceita inserção somente pelo RPC restrito ao
`service_role`. A consulta do owner continua protegida por
`paxinbot_require_owner()`.

## Validação antes de produção

1. aplicar a migração somente no branch de teste do Supabase;
2. implantar a branch `staging` na Vercel Preview;
3. confirmar `X-Paxinbot-Request-Id` nas respostas de API;
4. provocar um login inválido e confirmar o evento sem e-mail/IP bruto;
5. confirmar que login válido, checkout PIX/cartão e webhook continuam iguais;
6. abrir a Auditoria como owner e confirmar a junção cronológica;
7. seguir a Etapa 7 de `cloudflare-activation-guide.md` apenas na ativação
   final, depois da aprovação de todos os pacotes.
