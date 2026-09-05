# Complemento das 10 funcoes ausentes

Preparado a partir da auditoria enviada em 2026-09-04: 10 MISSING, 62 REVIEW,
9 OK. Nenhuma conexao ao Supabase nem alteracao em producao foi realizada neste
procedimento. Os arquivos sao de manutencao manual, nao migracoes de deploy.

Revisao de dispositivos: o diagnostico recebido mostrou 44 OK, 11 WILL_CREATE e
device_account_bindings ausente. O inventario posterior confirmou as colunas
approved_user_id, consumed_at e denied_at em device_authorizations. O complemento
foi ajustado com autorizacao do usuario; descarte copias anteriores do SQL.

## Arquivos e ordem

1. Preserve um backup do banco e o resultado anterior de `rpc_execute_audit.sql`.
   O backup do aplicativo NAO e backup do banco.
2. Como `postgres`, execute somente `supabase/diagnostics/missing_rpc_dependencies.sql`.
   Todos os resultados devem ser `OK` ou `WILL_CREATE` (somente para a tabela de
   eventos ausente). Se houver `MISSING_TABLE`, `MISSING_COLUMN`, `NOT_TABLE` ou
   `TYPE_MISMATCH`, pare e envie o resultado para revisao. Nao remova verificacoes.
3. Com dependencias compativeis, revise e execute o arquivo inteiro
   `supabase/remediation/20260904_restore_missing_rpcs.sql`. Ele verifica tambem
   os helpers de autenticacao, o proprietario de require_owner e os indices unicos
   necessarios aos ON CONFLICT. Se alguma das 10 funcoes ja existir, ele para SEM
   substituir a funcao existente. Esse comportamento e intencional, inclusive ao
   executar novamente um complemento que ja tenha sido aplicado.
4. Execute `supabase/diagnostics/rpc_execute_audit.sql`. Nao deve restar MISSING;
   os REVIEW das funcoes antigas ainda sao esperados nesta etapa.
5. Entao execute o corretivo anterior:
   `supabase/remediation/20260904_repair_rpc_execute_privileges.sql`.
6. Repita a auditoria: esperado somente OK e eventualmente OPTIONAL_ABSENT.
   Teste os fluxos do app/portal conforme o guia de permissoes.

Se ocorrer erro, a transacao nao confirma suas mudancas. Caso o editor mantenha
uma sessao em estado abortado, execute `rollback;`. Para ensaio, use uma COPIA do
SQL com somente o ultimo `commit;` trocado por `rollback;`; isso ainda adquire
locks temporarios. Nao aplique todas as migracoes antigas em massa.

## Conteudo

| Origem no repositorio | Funcoes recuperadas |
| --- | --- |
| 20260817_checkout.sql | owner_approve_order, owner_refund_order, owner_list_orders(text) |
| 20260822_usage_credits.sql | owner_kick_user, owner_set_user_ban, owner_reset_user_devices |
| 20260829_api_abuse_limits.sql | service_rate_limit_v2 |
| 20260830_site_security_observability.sql | record_site_security_event, owner_list_site_security_events |
| 20260831_database_least_privilege.sql | get_usage_runtime_state |

Os nomes acima possuem prefixo `paxinbot_`. A sobrecarga antiga
`paxinbot_owner_list_orders()` e preservada, nao substituida pela versao com text.

O complemento cria `site_security_events` somente se ausente, conforme a estrutura
ja prevista no codigo, usando o gerador de UUID nativo do PostgreSQL. Se a tabela
ja existe, sua estrutura deve ser compativel; nenhuma coluna sera acrescentada ou
removida. RLS e habilitado e acesso direto por PUBLIC, anon, authenticated e
service_role e revogado nessa tabela interna. Sao criados os indices operacionais
previstos, quando ausentes. O privilegio CREATE em public e retirado dos papeis
externos, sem mudar memberships ou papeis globais.

As 10 funcoes usam search_path fixo com pg_catalog primeiro e pg_temp por ultimo.
As administrativas exigem usuario identificado e a verificacao require_owner.
As tres de servidor exigem service_role explicitamente, inclusive quando a claim
esta nula. Parametros nulos relevantes sao rejeitados. Grants ficam limitados a
authenticated (administrativas) ou service_role (servidor), com conferencia de
permissoes efetivas antes do COMMIT.

Os corpos de negocio foram recuperados dos arquivos indicados, com a excecao de
owner_reset_user_devices detalhada abaixo, sem executar
nenhuma dessas operacoes durante a instalacao. Aprovar/reembolsar pedidos, banir
usuarios e redefinir acessos sao acoes administrativas posteriores, NAO chamadas
por este SQL. Em especial, a funcao de reembolso altera registros internos; nao
efetua estorno financeiro no Mercado Pago. A equivalencia desses fluxos com regras
comerciais especificas precisa ser validada em sandbox antes de uso operacional.

## Redefinicao de dispositivos (adaptacao aprovada)

O SQL historico referenciava device_account_bindings, ausente no banco informado.
Nao criamos essa tabela nem apagamos device_identities: a identidade criptografica
nao tem user_id e preserva bloqueios por maquina. A funcao agora:

1. Exige usuario autenticado, require_owner e p_user_id nao nulo.
2. Marca denied_at somente em device_authorizations da conta indicada, com
   approved_user_id correspondente, consumed_at nulo e denied_at nulo.
3. Revoga somente desktop_sessions da conta indicada ainda nao revogadas.
4. Registra owner.user_devices_reset com o ID da conta, sem segredos.

Essa ordem invalida os pedidos aprovados antes de revogar sessoes. Autorizações
consumidas, pedidos ainda sem usuario aprovado, outros usuarios e timestamps de
revogacao/negacao anteriores sao preservados. Nao altera identidades, banimentos,
creditos ou promotion_claims. Nao desassocia beneficios promocionais da maquina.
E uma redefinicao dos acessos existentes, nao um banimento da conta: uma nova
aprovacao legitima pelo navegador pode autorizar outro acesso. Nao e prometido
bloqueio permanente de aprovacoes concorrentes ou futuras. Os testes isolados
nao simulam a concorrencia dos RPCs implantados em producao.

As tres novas dependencias foram confirmadas pelo inventario enviado, mas a
consulta atualizada (58 campos) e o preflight transacional devem continuar sendo
usados para detectar mudancas posteriores no banco.

## Testes realizados

- Testes de contrato Node conferem as 10 funcoes, as 58 colunas, roles, RLS,
  transacao e recusa de sobrescrita.
- `scripts/verify-missing-rpcs.cjs` executa o SQL em PostgreSQL em memoria via
  PGlite 0.5.8, com roles e dados FICTICIOS. Nao possui URL nem credenciais do banco.
- 31 verificacoes: criacao; nenhuma operacao de negocio na instalacao; negacao de
  anon e usuario comum; chamadas owner; chamada server; claim nula; limitador;
  evento duplicado; banimento nulo; reaplicacao recusada; coluna ausente;
  heranca de EXECUTE indevida; execucao sequencial do corretivo anterior e auditoria;
  redefinicao restrita a conta, preservacao de identidades/bans/promocoes/creditos,
  repeticao sem reescrever timestamps e rejeicao de alvo nulo/identidade ausente.
- Os outros RPCs no teste de ACL sao stubs inertes. Isso testa a matriz de grants,
  nao valida toda a logica de negocio do site nem os corpos implantados no Supabase.

Para reproduzir, instale PGlite 0.5.8 em diretorio temporario, sem lifecycle scripts,
e defina `PAXINBOT_SQL_TEST_RUNTIME` com o caminho absoluto do modulo instalado.
Execute `node scripts/verify-missing-rpcs.cjs`. O runtime de teste nao e dependencia
de producao do site, e esses arquivos nao entram na saida publica.

Referencia: https://www.postgresql.org/docs/current/sql-createfunction.html
