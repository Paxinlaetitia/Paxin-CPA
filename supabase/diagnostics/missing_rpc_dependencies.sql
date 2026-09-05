-- Somente leitura; nao mostra dados pessoais ou credenciais.
-- OK: coluna compativel. WILL_CREATE: tabela de eventos ausente, criada pelo complemento.
-- Outros status: PARE e revise antes de executar o complemento.
with dependencies(table_name, column_name, expected_type) as (values
  ('auth.users', 'id', 'uuid'),
  ('auth.users', 'email', 'textlike'),
  ('public.orders', 'id', 'uuid'),
  ('public.orders', 'user_id', 'uuid'),
  ('public.orders', 'product_id', 'uuid'),
  ('public.orders', 'entitlement_id', 'uuid'),
  ('public.orders', 'status', 'textlike'),
  ('public.orders', 'currency', 'textlike'),
  ('public.orders', 'payment_provider', 'textlike'),
  ('public.orders', 'provider_status', 'textlike'),
  ('public.orders', 'paid_at', 'timestamptz'),
  ('public.orders', 'updated_at', 'timestamptz'),
  ('public.orders', 'created_at', 'timestamptz'),
  ('public.orders', 'subtotal_cents', 'integer'),
  ('public.orders', 'discount_cents', 'integer'),
  ('public.orders', 'amount_cents', 'integer'),
  ('public.products', 'id', 'uuid'),
  ('public.products', 'name', 'textlike'),
  ('public.products', 'access_kind', 'textlike'),
  ('public.products', 'duration_minutes', 'integer'),
  ('public.entitlements', 'id', 'uuid'),
  ('public.entitlements', 'user_id', 'uuid'),
  ('public.entitlements', 'kind', 'textlike'),
  ('public.entitlements', 'status', 'textlike'),
  ('public.entitlements', 'source', 'textlike'),
  ('public.entitlements', 'expires_at', 'timestamptz'),
  ('public.entitlements', 'revoked_at', 'timestamptz'),
  ('public.profiles', 'id', 'uuid'),
  ('public.profiles', 'disabled_at', 'timestamptz'),
  ('public.audit_events', 'user_id', 'uuid'),
  ('public.audit_events', 'event_type', 'textlike'),
  ('public.audit_events', 'metadata', 'jsonb'),
  ('public.desktop_sessions', 'user_id', 'uuid'),
  ('public.desktop_sessions', 'usage_grant_id', 'uuid'),
  ('public.desktop_sessions', 'revoked_at', 'timestamptz'),
  ('public.desktop_sessions', 'usage_paused_at', 'timestamptz'),
  ('public.desktop_sessions', 'last_seen_at', 'timestamptz'),
  ('public.usage_grants', 'user_id', 'uuid'),
  ('public.usage_grants', 'status', 'textlike'),
  ('public.usage_grants', 'revoked_at', 'timestamptz'),
  ('public.device_authorizations', 'approved_user_id', 'uuid'),
  ('public.device_authorizations', 'consumed_at', 'timestamptz'),
  ('public.device_authorizations', 'denied_at', 'timestamptz'),
  ('public.api_rate_limits', 'scope', 'textlike'),
  ('public.api_rate_limits', 'subject_hash', 'textlike'),
  ('public.api_rate_limits', 'window_started_at', 'timestamptz'),
  ('public.api_rate_limits', 'hits', 'integer'),
  ('public.site_security_events', 'id', 'uuid'),
  ('public.site_security_events', 'event_id', 'uuid'),
  ('public.site_security_events', 'request_id', 'uuid'),
  ('public.site_security_events', 'actor_user_id', 'uuid'),
  ('public.site_security_events', 'occurred_at', 'timestamptz'),
  ('public.site_security_events', 'event_type', 'textlike'),
  ('public.site_security_events', 'route', 'textlike'),
  ('public.site_security_events', 'subject_hash', 'textlike'),
  ('public.site_security_events', 'edge_trace_hash', 'textlike'),
  ('public.site_security_events', 'severity', 'smallint'),
  ('public.site_security_events', 'details', 'jsonb')
)
select d.table_name, d.column_name, d.expected_type,
  case when to_regclass(d.table_name) is null and d.table_name = 'public.site_security_events'
    then 'WILL_CREATE'
    when c.oid is null then 'MISSING_TABLE'
    when c.relkind not in ('r', 'p') then 'NOT_TABLE'
    when a.attnum is null then 'MISSING_COLUMN'
    when (d.expected_type = 'textlike' and t.typcategory in ('S', 'E'))
      or (d.expected_type <> 'textlike' and a.atttypid = to_regtype(d.expected_type)) then 'OK'
    else 'TYPE_MISMATCH' end as status,
  format_type(a.atttypid, a.atttypmod) as actual_type
from dependencies d
left join pg_class c on c.oid = to_regclass(d.table_name)
left join pg_attribute a on a.attrelid = c.oid and a.attname = d.column_name
  and a.attnum > 0 and not a.attisdropped
left join pg_type t on t.oid = a.atttypid
order by status, table_name, column_name;
