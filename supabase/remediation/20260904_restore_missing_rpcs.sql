-- Complemento MANUAL das 10 assinaturas MISSING da auditoria recebida.
-- Nao executado em producao. Preserve backup do banco e o inventario de ACL.
-- Nao substitui funcoes existentes. Nao chama funcoes de negocio.
-- Aplicar ANTES de 20260904_repair_rpc_execute_privileges.sql, em sessao postgres.
begin;
set local lock_timeout = '5s';
set local statement_timeout = '45s';
set local search_path = pg_catalog, public, auth, pg_temp;

create temporary table paxinbot_missing_rpc_20260904 (
 signature text primary key, service_only boolean not null
) on commit drop;
insert into pg_temp.paxinbot_missing_rpc_20260904 values
  ('public.paxinbot_owner_approve_order(uuid)', false),
  ('public.paxinbot_owner_refund_order(uuid)', false),
  ('public.paxinbot_owner_list_orders(text)', false),
  ('public.paxinbot_owner_kick_user(uuid)', false),
  ('public.paxinbot_owner_set_user_ban(uuid,boolean,text)', false),
  ('public.paxinbot_owner_reset_user_devices(uuid)', false),
  ('public.paxinbot_service_rate_limit_v2(text,text,integer,integer,integer)', true),
  ('public.paxinbot_record_site_security_event(uuid,uuid,text,smallint,text,uuid,text,text,jsonb)', true),
  ('public.paxinbot_owner_list_site_security_events(integer)', false),
  ('public.paxinbot_get_usage_runtime_state(uuid,uuid)', true);

do $preflight$
declare v_error text;
begin
  if current_user <> 'postgres' then raise exception 'Execute como postgres.'; end if;
  select string_agg(signature, ', ') into v_error
  from pg_temp.paxinbot_missing_rpc_20260904 where to_regprocedure(signature) is not null;
  if v_error is not null then
    raise exception 'Funcoes ja existem; nao serao substituidas. Rode nova auditoria: %', v_error;
  end if;
  if to_regprocedure('auth.uid()') is null or to_regprocedure('auth.role()') is null
    or to_regprocedure('public.paxinbot_require_owner()') is null then
    raise exception 'Dependencia de autorizacao ausente. Nenhuma funcao sera criada.';
  end if;
  if not exists (select 1 from pg_proc p where p.oid = to_regprocedure('public.paxinbot_require_owner()')
    and p.proowner = (select oid from pg_roles where rolname = 'postgres') and p.prosecdef) then
    raise exception 'Proprietario/contrato de paxinbot_require_owner inesperado; revise.';
  end if;
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
  ), checked as (
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
  )
  select string_agg(table_name || '.' || column_name || ': ' || status, ', ')
    into v_error from checked where status not in ('OK', 'WILL_CREATE');
  if v_error is not null then raise exception 'Estrutura incompativel: %', v_error; end if;

  -- ON CONFLICT(scope, subject_hash) precisa de uma chave unica compativel.
  if not exists (
    select 1 from pg_index i
    where i.indrelid = to_regclass('public.api_rate_limits') and i.indisunique
      and i.indisvalid and i.indimmediate and i.indpred is null and i.indexprs is null
      and i.indnkeyatts = 2
      and (select array_agg(a.attname::text order by a.attname)
        from unnest(i.indkey::smallint[]) with ordinality k(attnum, position)
        join pg_attribute a on a.attrelid = i.indrelid and a.attnum = k.attnum
        where k.position <= i.indnkeyatts) = array['scope','subject_hash']::text[]
  ) then raise exception 'Chave unica api_rate_limits(scope,subject_hash) ausente.'; end if;
end;
$preflight$;

-- Evita objetos criados por papeis externos no search_path de definers.
revoke create on schema public from public, anon, authenticated, service_role;

create table if not exists public.site_security_events (
  id uuid primary key default pg_catalog.gen_random_uuid(),
  event_id uuid not null unique,
  request_id uuid not null,
  occurred_at timestamptz not null default now(),
  event_type text not null check (event_type in (
    'edge.host_rejected','csrf.rejected','rate_limit.blocked',
    'auth.login_rejected','auth.code_rejected','auth.session_rejected',
    'auth.password_changed','checkout.provider_failure',
    'webhook.signature_rejected','webhook.provider_failure',
    'webhook.payment_processed','admin.access_denied'
  )),
  severity smallint not null check (severity between 0 and 100),
  route text not null check (route ~ '^/api/[A-Za-z0-9_./-]{1,115}$'),
  actor_user_id uuid references auth.users(id) on delete set null,
  subject_hash text check (subject_hash is null or subject_hash ~ '^[a-f0-9]{64}$'),
  edge_trace_hash text check (edge_trace_hash is null or edge_trace_hash ~ '^[a-f0-9]{64}$'),
  details jsonb not null default '{}'::jsonb check (
    jsonb_typeof(details) = 'object' and octet_length(details::text) <= 768
  )
);
alter table public.site_security_events enable row level security;
revoke all on table public.site_security_events from public, anon, authenticated, service_role;

do $event_constraint$
begin
  if not exists (
    select 1 from pg_index i
    where i.indrelid = 'public.site_security_events'::regclass and i.indisunique
      and i.indisvalid and i.indimmediate and i.indpred is null and i.indexprs is null
      and i.indnkeyatts = 1
      and (select a.attname from pg_attribute a where a.attrelid = i.indrelid
        and a.attnum = i.indkey[0]) = 'event_id'
  ) then raise exception 'Chave unica site_security_events(event_id) ausente.'; end if;
end;
$event_constraint$;

create index if not exists site_security_events_time_idx on public.site_security_events(occurred_at desc);
create index if not exists site_security_events_type_idx on public.site_security_events(event_type, occurred_at desc);
create index if not exists site_security_events_actor_idx on public.site_security_events(actor_user_id, occurred_at desc) where actor_user_id is not null;
create index if not exists api_rate_limits_window_started_idx on public.api_rate_limits(window_started_at);

-- Origem: 20260817_checkout.sql; somente autenticacao/search_path/NULL reforcados.
create function public.paxinbot_owner_approve_order(p_order_id uuid)
returns jsonb language plpgsql security definer set search_path = pg_catalog, public, auth, pg_temp
as $$
declare
  v_order public.orders%rowtype;
  v_product public.products%rowtype;
  v_entitlement_id uuid;
  v_base timestamptz;
  v_expires timestamptz;
begin
  if auth.uid() is null then raise exception 'not_authenticated'; end if;
  perform public.paxinbot_require_owner();
  select * into v_order from public.orders where id = p_order_id for update;
  if not found then raise exception 'order_not_found'; end if;
  if v_order.status = 'paid' then raise exception 'order_already_paid'; end if;

  select * into v_product from public.products where id = v_order.product_id;

  v_entitlement_id := v_order.entitlement_id;
  if v_entitlement_id is null and v_product.id is not null then
    if v_product.access_kind = 'lifetime' then
      insert into public.entitlements (user_id, kind, expires_at, source)
      values (v_order.user_id, 'lifetime', null, 'owner-approve:' || v_order.id::text)
      returning id into v_entitlement_id;
    else
      select greatest(now(), coalesce(max(e.expires_at), now())) into v_base
      from public.entitlements e
      where e.user_id = v_order.user_id and e.kind = 'duration' and e.status = 'active' and e.expires_at > now();
      v_expires := coalesce(v_base, now()) + make_interval(mins => coalesce(v_product.duration_minutes, 60));
      insert into public.entitlements (user_id, kind, expires_at, source)
      values (v_order.user_id, 'duration', v_expires, 'owner-approve:' || v_order.id::text)
      returning id into v_entitlement_id;
    end if;
  end if;

  update public.orders
  set status = 'paid',
      paid_at = coalesce(paid_at, now()),
      provider_status = 'manual_approved',
      entitlement_id = coalesce(entitlement_id, v_entitlement_id),
      updated_at = now()
  where id = v_order.id;

  insert into public.audit_events (user_id, event_type, metadata)
  values (auth.uid(), 'owner.order_approved', jsonb_build_object('orderId', p_order_id, 'targetUserId', v_order.user_id));

  return jsonb_build_object('ok', true);
end;
$$;
revoke all on function public.paxinbot_owner_approve_order(uuid) from public, anon, authenticated, service_role;
grant execute on function public.paxinbot_owner_approve_order(uuid) to authenticated;

-- Origem: 20260817_checkout.sql; somente autenticacao/search_path/NULL reforcados.
create function public.paxinbot_owner_refund_order(p_order_id uuid)
returns jsonb language plpgsql security definer set search_path = pg_catalog, public, auth, pg_temp
as $$
declare
  v_order public.orders%rowtype;
begin
  if auth.uid() is null then raise exception 'not_authenticated'; end if;
  perform public.paxinbot_require_owner();
  select * into v_order from public.orders where id = p_order_id for update;
  if not found then raise exception 'order_not_found'; end if;
  if v_order.status = 'refunded' then raise exception 'order_already_refunded'; end if;

  if v_order.entitlement_id is not null then
    update public.entitlements
    set status = 'revoked', revoked_at = now()
    where id = v_order.entitlement_id and status = 'active';
  end if;

  update public.entitlements
  set status = 'revoked', revoked_at = now()
  where user_id = v_order.user_id and source like '%' || v_order.id::text || '%' and status = 'active';

  update public.desktop_sessions
  set revoked_at = now()
  where user_id = v_order.user_id and revoked_at is null;

  update public.orders
  set status = 'refunded',
      provider_status = 'manual_refunded',
      updated_at = now()
  where id = v_order.id;

  insert into public.audit_events (user_id, event_type, metadata)
  values (auth.uid(), 'owner.order_refunded', jsonb_build_object('orderId', p_order_id, 'targetUserId', v_order.user_id));

  return jsonb_build_object('ok', true);
end;
$$;
revoke all on function public.paxinbot_owner_refund_order(uuid) from public, anon, authenticated, service_role;
grant execute on function public.paxinbot_owner_refund_order(uuid) to authenticated;

-- Origem: 20260817_checkout.sql; somente autenticacao/search_path/NULL reforcados.
create function public.paxinbot_owner_list_orders(p_query text default '')
returns jsonb language plpgsql stable security definer set search_path = pg_catalog, public, auth, pg_temp
as $$
declare
  v_query text := lower(trim(coalesce(p_query, '')));
begin
  if auth.uid() is null then raise exception 'not_authenticated'; end if;
  perform public.paxinbot_require_owner();
  return coalesce((select jsonb_agg(row_to_json(x) order by x."createdAt" desc) from (
    select o.id, u.email, coalesce(p.name, 'Produto Paxinbot') as "productName", o.subtotal_cents as "subtotalCents",
      o.discount_cents as "discountCents", o.amount_cents as "amountCents", o.currency,
      case
        when o.status = 'pending' and o.created_at < now() - interval '24 hours' then 'expired'
        else o.status
      end as status,
      o.payment_provider as "paymentProvider", coalesce(o.provider_status, '') as "providerStatus",
      o.created_at as "createdAt", o.paid_at as "paidAt"
    from public.orders o join auth.users u on u.id = o.user_id
    left join public.products p on p.id = o.product_id
    where v_query = ''
      or lower(u.email) like '%' || v_query || '%'
      or lower(o.id::text) like '%' || v_query || '%'
      or lower(coalesce(p.name, '')) like '%' || v_query || '%'
      or lower(o.status) like '%' || v_query || '%'
    order by o.created_at desc limit 200
  ) x), '[]'::jsonb);
end;
$$;
revoke all on function public.paxinbot_owner_list_orders(text) from public, anon, authenticated, service_role;
grant execute on function public.paxinbot_owner_list_orders(text) to authenticated;

-- Origem: 20260822_usage_credits.sql; somente autenticacao/search_path/NULL reforcados.
create function public.paxinbot_owner_kick_user(p_user_id uuid)
returns jsonb language plpgsql security definer set search_path = pg_catalog, public, auth, pg_temp
as $$
begin
  if auth.uid() is null then raise exception 'not_authenticated'; end if;
  perform public.paxinbot_require_owner();
  if p_user_id is null then raise exception 'invalid_user'; end if;
  update public.desktop_sessions
  set revoked_at = now()
  where user_id = p_user_id and revoked_at is null;
  insert into public.audit_events (user_id, event_type, metadata)
  values (auth.uid(), 'owner.user_kicked', jsonb_build_object('targetUserId', p_user_id));
  return jsonb_build_object('ok', true);
end;
$$;
revoke all on function public.paxinbot_owner_kick_user(uuid) from public, anon, authenticated, service_role;
grant execute on function public.paxinbot_owner_kick_user(uuid) to authenticated;

-- Origem: 20260822_usage_credits.sql; somente autenticacao/search_path/NULL reforcados.
create function public.paxinbot_owner_set_user_ban(p_user_id uuid, p_banned boolean, p_reason text default null)
returns jsonb language plpgsql security definer set search_path = pg_catalog, public, auth, pg_temp
as $$
begin
  if auth.uid() is null then raise exception 'not_authenticated'; end if;
  perform public.paxinbot_require_owner();
  if p_banned is null then raise exception 'invalid_ban_state'; end if;
  if p_user_id is null then raise exception 'invalid_user'; end if;
  if p_banned then
    update public.profiles set disabled_at = coalesce(disabled_at, now()) where id = p_user_id;
    update public.entitlements set status = 'revoked', revoked_at = now() where user_id = p_user_id and status = 'active';
    update public.usage_grants set status = 'revoked', revoked_at = now() where user_id = p_user_id and status in ('available', 'active');
    update public.desktop_sessions set revoked_at = now() where user_id = p_user_id and revoked_at is null;
    insert into public.audit_events (user_id, event_type, metadata)
    values (auth.uid(), 'owner.user_banned', jsonb_build_object('targetUserId', p_user_id, 'reason', p_reason));
  else
    update public.profiles set disabled_at = null where id = p_user_id;
    insert into public.audit_events (user_id, event_type, metadata)
    values (auth.uid(), 'owner.user_unbanned', jsonb_build_object('targetUserId', p_user_id));
  end if;
  return jsonb_build_object('ok', true);
end;
$$;
revoke all on function public.paxinbot_owner_set_user_ban(uuid,boolean,text) from public, anon, authenticated, service_role;
grant execute on function public.paxinbot_owner_set_user_ban(uuid,boolean,text) to authenticated;

-- Adaptacao aprovada: revoga acesso da conta sem apagar identidades, bans ou promocoes.
-- device_account_bindings era uma referencia historica sem tabela correspondente.
create function public.paxinbot_owner_reset_user_devices(p_user_id uuid)
returns jsonb language plpgsql security definer set search_path = pg_catalog, public, auth, pg_temp
as $$
begin
  if auth.uid() is null then raise exception 'not_authenticated'; end if;
  perform public.paxinbot_require_owner();
  if p_user_id is null then raise exception 'invalid_user'; end if;
  -- Primeiro invalida pedidos aprovados ainda nao consumidos; depois revoga sessoes.
  -- Preserva timestamps de negacoes/revogacoes anteriores e o historico consumido.
  update public.device_authorizations set denied_at = now()
    where approved_user_id = p_user_id and consumed_at is null and denied_at is null;
  update public.desktop_sessions set revoked_at = now() where user_id = p_user_id and revoked_at is null;
  insert into public.audit_events (user_id, event_type, metadata)
  values (auth.uid(), 'owner.user_devices_reset', jsonb_build_object('targetUserId', p_user_id));
  return jsonb_build_object('ok', true);
end;
$$;
revoke all on function public.paxinbot_owner_reset_user_devices(uuid) from public, anon, authenticated, service_role;
grant execute on function public.paxinbot_owner_reset_user_devices(uuid) to authenticated;

-- Origem: 20260829_api_abuse_limits.sql; somente autenticacao/search_path/NULL reforcados.
create function public.paxinbot_service_rate_limit_v2(
  p_scope text,
  p_subject_hash text,
  p_limit integer,
  p_window_seconds integer,
  p_cost integer default 1
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, auth, pg_temp
as $$
declare
  v_row public.api_rate_limits%rowtype;
  v_reset_after integer;
begin
  if auth.role() is distinct from 'service_role' then raise exception 'service_role_required'; end if;
  if p_scope is null or p_subject_hash is null or p_limit is null or p_window_seconds is null or p_cost is null then
    raise exception 'invalid_rate_limit';
  end if;
  if p_scope !~ '^[a-z0-9_]{3,40}$'
     or p_subject_hash !~ '^[a-f0-9]{64}$'
     or p_limit not between 1 and 1000
     or p_window_seconds not between 10 and 86400
     or p_cost not between 1 and 100 then
    raise exception 'invalid_rate_limit';
  end if;

  insert into public.api_rate_limits(scope, subject_hash, window_started_at, hits)
  values (p_scope, p_subject_hash, now(), 0)
  on conflict (scope, subject_hash) do nothing;

  select * into v_row
  from public.api_rate_limits
  where scope = p_scope and subject_hash = p_subject_hash
  for update;

  if v_row.window_started_at + make_interval(secs => p_window_seconds) <= now() then
    update public.api_rate_limits
    set window_started_at = now(), hits = p_cost
    where scope = p_scope and subject_hash = p_subject_hash
    returning * into v_row;
  else
    update public.api_rate_limits
    set hits = hits + p_cost
    where scope = p_scope and subject_hash = p_subject_hash
    returning * into v_row;
  end if;

  v_reset_after := greatest(1, least(
    p_window_seconds,
    ceil(extract(epoch from (v_row.window_started_at + make_interval(secs => p_window_seconds) - now())))::integer
  ));

  -- Aproximadamente 1 em cada 256 sujeitos aciona uma limpeza leve. Como o
  -- valor é um HMAC secreto, um cliente não consegue escolher deliberadamente
  -- quando a coleta ocorre. Janelas de até 24 horas permanecem intactas.
  if get_byte(decode(substr(p_subject_hash, 1, 2), 'hex'), 0) = 0 then
    delete from public.api_rate_limits
    where window_started_at < now() - interval '2 days';
  end if;

  return jsonb_build_object(
    'allowed', v_row.hits <= p_limit,
    'remaining', greatest(0, p_limit - v_row.hits),
    'resetAfter', v_reset_after
  );
end;
$$;
revoke all on function public.paxinbot_service_rate_limit_v2(text,text,integer,integer,integer) from public, anon, authenticated, service_role;
grant execute on function public.paxinbot_service_rate_limit_v2(text,text,integer,integer,integer) to service_role;

-- Origem: 20260830_site_security_observability.sql; somente autenticacao/search_path/NULL reforcados.
create function public.paxinbot_record_site_security_event(
  p_event_id uuid,
  p_request_id uuid,
  p_event_type text,
  p_severity smallint,
  p_route text,
  p_actor_user_id uuid default null,
  p_subject_hash text default null,
  p_edge_trace_hash text default null,
  p_details jsonb default '{}'::jsonb
)
returns boolean language plpgsql security definer set search_path = pg_catalog, public, auth, pg_temp
as $$
declare v_details jsonb := coalesce(p_details, '{}'::jsonb);
begin
  if auth.role() is distinct from 'service_role' then raise exception 'service_role_required'; end if;
  if p_event_type is null or p_severity is null or p_route is null then raise exception 'site_security_event_invalid'; end if;
  if p_event_id is null or p_request_id is null or p_event_type not in (
    'edge.host_rejected','csrf.rejected','rate_limit.blocked',
    'auth.login_rejected','auth.code_rejected','auth.session_rejected',
    'auth.password_changed','checkout.provider_failure',
    'webhook.signature_rejected','webhook.provider_failure',
    'webhook.payment_processed','admin.access_denied'
  ) or p_severity not between 0 and 100
    or p_route !~ '^/api/[A-Za-z0-9_./-]{1,115}$'
    or (p_actor_user_id is not null and not exists(select 1 from auth.users where id=p_actor_user_id))
    or (p_subject_hash is not null and p_subject_hash !~ '^[a-f0-9]{64}$')
    or (p_edge_trace_hash is not null and p_edge_trace_hash !~ '^[a-f0-9]{64}$')
    or jsonb_typeof(v_details) <> 'object' or octet_length(v_details::text) > 768
    or exists(select 1 from jsonb_object_keys(v_details) key
      where key not in ('reasonCode','outcome','provider','scope','method','status'))
    or exists(select 1 from jsonb_each_text(v_details) entry
      where entry.value !~ '^[A-Za-z0-9_.:-]{1,80}$')
  then raise exception 'site_security_event_invalid'; end if;

  insert into public.site_security_events(
    event_id,request_id,event_type,severity,route,actor_user_id,
    subject_hash,edge_trace_hash,details
  ) values (
    p_event_id,p_request_id,p_event_type,p_severity,p_route,p_actor_user_id,
    p_subject_hash,p_edge_trace_hash,v_details
  ) on conflict(event_id) do nothing;

  -- Limpeza probabilística: aproximadamente 1/16 das inserções remove eventos
  -- antigos, sem exigir cron ou extensão adicional no projeto Supabase.
  if left(p_event_id::text, 1) = '0' then
    delete from public.site_security_events where occurred_at < now() - interval '90 days';
  end if;
  return true;
end;
$$;
revoke all on function public.paxinbot_record_site_security_event(uuid,uuid,text,smallint,text,uuid,text,text,jsonb) from public, anon, authenticated, service_role;
grant execute on function public.paxinbot_record_site_security_event(uuid,uuid,text,smallint,text,uuid,text,text,jsonb) to service_role;

-- Origem: 20260830_site_security_observability.sql; somente autenticacao/search_path/NULL reforcados.
create function public.paxinbot_owner_list_site_security_events(p_limit integer default 200)
returns jsonb language plpgsql stable security definer set search_path = pg_catalog, public, auth, pg_temp
as $$
begin
  if auth.uid() is null then raise exception 'not_authenticated'; end if;
  perform public.paxinbot_require_owner();
  return coalesce((select jsonb_agg(row_to_json(x) order by x."createdAt" desc) from (
    select e.event_id as id, e.event_type as "eventType", u.email,
      e.occurred_at as "createdAt", e.severity, e.route,
      e.details || jsonb_build_object('requestId',e.request_id) as metadata
    from public.site_security_events e
    left join auth.users u on u.id=e.actor_user_id
    order by e.occurred_at desc
    limit least(greatest(coalesce(p_limit,200),1),500)
  ) x), '[]'::jsonb);
end;
$$;
revoke all on function public.paxinbot_owner_list_site_security_events(integer) from public, anon, authenticated, service_role;
grant execute on function public.paxinbot_owner_list_site_security_events(integer) to authenticated;

-- Origem: 20260831_database_least_privilege.sql; somente autenticacao/search_path/NULL reforcados.
create function public.paxinbot_get_usage_runtime_state(
  p_user_id uuid,
  p_usage_grant_id uuid
)
returns jsonb language plpgsql stable security definer
set search_path = pg_catalog, public, auth, pg_temp
as $$
declare v_running boolean := false;
begin
  if auth.role() is distinct from 'service_role' then raise exception 'service_role_required'; end if;
  if p_user_id is null or p_usage_grant_id is null then raise exception 'runtime_query_invalid'; end if;
  select exists(
    select 1 from public.desktop_sessions s
    where s.user_id=p_user_id and s.usage_grant_id=p_usage_grant_id
      and s.revoked_at is null and s.usage_paused_at is null
      and s.last_seen_at > now() - interval '25 seconds'
  ) into v_running;
  return jsonb_build_object('running',v_running);
end;
$$;
revoke all on function public.paxinbot_get_usage_runtime_state(uuid,uuid) from public, anon, authenticated, service_role;
grant execute on function public.paxinbot_get_usage_runtime_state(uuid,uuid) to service_role;

do $verify$
declare v record; v_oid oid;
begin
  for v in select * from pg_temp.paxinbot_missing_rpc_20260904 loop
    v_oid := to_regprocedure(v.signature);
    if v_oid is null then raise exception 'Funcao nao criada: %', v.signature; end if;
    if has_function_privilege('anon', v_oid, 'EXECUTE')
      or has_function_privilege('authenticated', v_oid, 'EXECUTE') <> (not v.service_only)
      or has_function_privilege('service_role', v_oid, 'EXECUTE') <> v.service_only
      or exists(select 1 from pg_proc p, lateral aclexplode(coalesce(p.proacl, acldefault('f',p.proowner))) acl
        where p.oid = v_oid and acl.grantee = 0 and acl.privilege_type = 'EXECUTE')
    then raise exception 'ACL inesperada: %. Transacao cancelada.', v.signature; end if;
  end loop;
  if has_table_privilege('anon','public.site_security_events','SELECT,INSERT,UPDATE,DELETE')
    or has_table_privilege('authenticated','public.site_security_events','SELECT,INSERT,UPDATE,DELETE')
    or has_table_privilege('service_role','public.site_security_events','SELECT,INSERT,UPDATE,DELETE')
  then raise exception 'Acesso direto inesperado a site_security_events.'; end if;
end;
$verify$;
commit;
