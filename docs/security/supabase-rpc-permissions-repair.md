# Correcao dos alertas de permissoes RPC

Status: SQL preparado localmente. Nenhuma alteracao aplicada ao Supabase.
E uma correcao manual de ACL existentes em `supabase/remediation`, nao uma
migracao automatica de release. O bloqueio do release-audit contra mudancas
de grants nas migracoes continua intacto; esta correcao tem testes proprios.

## Ordem de execucao

A auditoria recebida em 2026-09-04 identificou 10 funcoes ausentes. Para esse
resultado, siga primeiro `supabase-missing-rpcs.md` e sua consulta de dependencias.
O corretivo de permissoes abaixo continua recusando a execucao com funcoes ausentes.

1. No SQL Editor, selecione o papel `postgres`. Execute somente
   `supabase/diagnostics/rpc_execute_audit.sql` e exporte o resultado antes da
   correcao. Ele registra proprietario, ACL e permissoes efetivas, sem dados
   de clientes ou credenciais. Esse inventario NAO substitui um backup do banco;
   preserve um backup/snapshot conforme a disponibilidade do projeto.
2. Se aparecer `MISSING`, pare e envie o resultado para revisao. O codigo atual
   espera as migracoes anteriores, ate `20260903_authorized_devices_active_only.sql`.
   Nao aplique migracoes antigas em massa nem remova a verificacao de requisitos.
   `OPTIONAL_ABSENT` para `paxinbot_owner_list_orders()` e permitido: a assinatura
   com argumento `text` e a atual. Sobrecargas com parametros diferentes sao
   objetos diferentes no PostgreSQL.
3. Revise o inventario antes de executar
   `supabase/remediation/20260904_repair_rpc_execute_privileges.sql` por inteiro.
   Para ensaiar a correcao sem persistir, use uma COPIA do texto e substitua apenas
   o ultimo `commit;` por `rollback;`. O ensaio ainda adquire locks temporarios.
4. Execute a auditoria novamente. Resultado esperado: `OK` e, no maximo,
   `OPTIONAL_ABSENT`. Nenhum `REVIEW` ou `MISSING`.
5. Confira o catalogo sem login, login e conta do cliente, autorizacao e validacao
   da sessao desktop, painel owner e acesso aos modulos protegidos. Teste checkout
   e webhook em ambiente de teste/sandbox, sem cobranca real. Uma conta comum deve
   continuar sem conseguir executar operacoes de owner.

Se o SQL falhar, a transacao nao confirma os grants. Caso a sessao do editor fique
em transacao abortada, execute `rollback;`. Nao contorne o erro com `CASCADE`,
remocao de memberships, `SECURITY INVOKER` em massa ou permissoes amplas.

## O que muda

- Corrige EXECUTE apenas em funcoes `public.paxinbot_*` e no trigger
  `public.handle_new_auth_user`. Nao altera funcoes de extensoes ou de auth/storage.
- Remove permissoes de PUBLIC, anon, authenticated e service_role nesse conjunto,
  reabrindo apenas 67 assinaturas revisadas, conforme o contrato existente do site.
  As funcoes precisam existir; este arquivo nao cria logica de negocio.
- Somente o catalogo recebe anon. Conta e painel recebem authenticated e continuam
  dependendo de validacoes internas de identidade/owner. Confirmacao de pagamento,
  sessoes desktop v3 e autorizacao de release ficam exclusivos de service_role.
- Helpers internos, triggers, RPCs antigos e sobrecargas desconhecidas nao recebem
  EXECUTE pela API. Funcoes SECURITY DEFINER chamam helpers como seu proprietario.
- Confere permissoes efetivas antes de COMMIT, incluindo concessoes herdadas. Se
  uma heranca mantiver acesso indevido, aborta em vez de modificar roles globais.
- Nao altera tabelas, dados, RLS, politicas, triggers ou corpos das funcoes.

O script trata ACL existentes, nao configura privilegios padrao para futuros
objetos. Novas funcoes exigem revisao e REVOKE/GRANT explicitos na mesma transacao.
A migracao antiga de least privilege trata defaults, mas nao deve ser reaplicada
cegamente: ela tambem muda tabelas e sequencias fora do escopo desta correcao.

## Alertas que podem permanecer

- SECURITY DEFINER para o catalogo anonimo e para RPCs de usuarios autenticados:
  exposicao intencional, sujeita as verificacoes internas. Esta correcao de ACL nao
  prova que os corpos das funcoes implantadas sejam identicos ao codigo local.
- RLS Enabled No Policy: manter nas tabelas internas sem acesso direto. Nao criar
  politicas permissivas apenas para limpar o painel.
- Leaked Password Protection: configuracao do Auth, nao de grants SQL. A habilitacao
  depende do plano; este procedimento nao altera assinatura ou cria custos.

## Validacao e limites

Os testes locais de contrato conferem matriz de permissoes, escopo, protecoes
transacionais e cobertura das rotas. Nao substituem executar o SQL e testar os
fluxos em PostgreSQL/Supabase. A auditoria exportada e um registro anterior das
permissoes, nao um script automatico de rollback; nao restaure grants amplos para
corrigir uma unica rota. Investigue a assinatura e o papel exatos envolvidos.

Referencias oficiais:
- https://www.postgresql.org/docs/current/sql-revoke.html
- https://supabase.com/docs/guides/database/functions
- https://supabase.com/docs/guides/database/postgres/row-level-security
- https://supabase.com/docs/guides/auth/password-security
