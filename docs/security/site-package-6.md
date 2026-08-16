# Segurança do site — pacote 6

O Pacote 6 reduz a superfície do Data API do Supabase. O modelo passa de
privilégios herdados para exposição opt-in. Nada é aplicado ao banco, Vercel ou
Cloudflare automaticamente.

## Implementado

- bloqueio de `CREATE` no schema `public` para papéis da Data API;
- privilégios padrão de tabelas, sequências e funções revogados;
- acesso direto a todas as tabelas de `public` removido de `anon`,
  `authenticated` e `service_role`;
- funções públicas revogadas e RPCs reabertos por três allowlists: catálogo
  anônimo, sessão autenticada e backend Vercel;
- RPCs v2/legados permanecem fechados;
- funções owner continuam exigindo `paxinbot_require_owner()` no banco;
- consulta direta do backend à tabela `desktop_sessions` substituída por um RPC
  mínimo, exclusivo do `service_role`;
- tabelas continuam com RLS mesmo sem acesso direto, fornecendo uma segunda
  barreira caso um grant seja criado incorretamente no futuro.

## Migração necessária

Aplicar no ambiente de teste depois do Pacote 5:

`supabase/migrations/20260831_database_least_privilege.sql`

Essa migração altera grants de todos os objetos no schema `public`. Não deve ser
executada isoladamente em produção. Primeiro publique o código correspondente
no preview e teste cada fluxo listado abaixo.

## Validação obrigatória no preview

1. catálogo público e página de planos;
2. cadastro, senha, Google, passkey e recuperação;
3. área do cliente, suporte, dispositivos e atividades;
4. todas as consultas e alterações do painel owner;
5. checkout PIX, Checkout Pro e webhook do Mercado Pago;
6. autorização, polling, sessão, pausa e módulos protegidos do aplicativo;
7. contador de uso em execução na área do cliente;
8. Database > Security Advisor no Supabase.

O Advisor pode listar RPCs `SECURITY DEFINER` concedidos a `authenticated`.
Compare os nomes com a allowlist da migração. Qualquer função fora dela é uma
falha e deve permanecer sem `EXECUTE`.

## Cloudflare

Este pacote não exige regra adicional. A Etapa 8 do guia cumulativo cobre a
revisão de DNS e garante que nenhuma credencial do Supabase seja armazenada na
Cloudflare ou enviada ao navegador.
