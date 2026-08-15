-- Paxinbot: endurecimento do login do aplicativo.
-- O executável é um cliente público. Somente o backend da Vercel pode chamar
-- estas funções; nenhuma chave secreta ou permissão administrativa vai no app.

create table if not exists public.api_rate_limits (
  scope text not null,
  subject_hash text not null,
  window_started_at timestamptz not null default now(),
  hits integer not null default 0 check (hits >= 0),
  primary key (scope, subject_hash)
);

alter table public.api_rate_limits enable row level security;
revoke all on table public.api_rate_limits from public, anon, authenticated;

alter table public.device_authorizations
  add column if not exists last_polled_at timestamptz,
  add column if not exists poll_count integer not null default 0,
  add column if not exists approved_at timestamptz;

alter table public.desktop_sessions
  add column if not exists app_version text;

create or replace function public.paxinbot_service_rate_limit(
  p_scope text,
  p_subject_hash text,
  p_limit integer,
  p_window_seconds integer
)
returns boolean
language plpgsql
security definer
set search_path = public
as $$
declare
  v_row public.api_rate_limits%rowtype;
begin
  if p_scope !~ '^[a-z0-9_]{3,40}$'
     or p_subject_hash !~ '^[a-f0-9]{64}$'
     or p_limit not between 1 and 1000
     or p_window_seconds not between 10 and 86400 then
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
    set window_started_at = now(), hits = 1
    where scope = p_scope and subject_hash = p_subject_hash;
    return true;
  end if;

  update public.api_rate_limits
  set hits = hits + 1
  where scope = p_scope and subject_hash = p_subject_hash
  returning * into v_row;

  return v_row.hits <= p_limit;
end;
$$;

create or replace function public.paxinbot_device_start_v2(
  p_request_id uuid,
  p_secret_hash text,
  p_user_code text,
  p_device_name text,
  p_app_version text
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare v_expires_at timestamptz := now() + interval '10 minutes';
begin
  if p_secret_hash !~ '^[a-f0-9]{64}$'
     or p_user_code !~ '^[A-HJ-NP-Z2-9]{4}(-[A-HJ-NP-Z2-9]{4}){2}$'
     or length(trim(p_device_name)) not between 1 and 80
     or p_device_name ~ '[[:cntrl:]]'
     or p_app_version !~ '^[0-9]{1,4}(\.[0-9]{1,4}){1,3}(-[0-9A-Za-z.-]{1,24})?$' then
    raise exception 'invalid_device_request';
  end if;

  insert into public.device_authorizations
    (id, secret_hash, user_code, device_name, app_version, expires_at)
  values
    (p_request_id, p_secret_hash, p_user_code, trim(p_device_name), p_app_version, v_expires_at);

  return jsonb_build_object('expiresAt', v_expires_at);
end;
$$;

create or replace function public.paxinbot_device_approve_v2(
  p_request_id uuid,
  p_user_code text,
  p_user_id uuid
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare v_device public.device_authorizations%rowtype;
begin
  if p_user_id is null
     or not exists (select 1 from public.profiles where id = p_user_id and disabled_at is null)
     or not exists (select 1 from public.paxinbot_active_entitlement(p_user_id)) then
    raise exception 'no_active_access';
  end if;

  select * into v_device
  from public.device_authorizations
  where id = p_request_id and user_code = upper(trim(p_user_code))
  for update;

  if not found or v_device.expires_at <= now() or v_device.consumed_at is not null
     or v_device.denied_at is not null or v_device.approved_user_id is not null then
    raise exception 'device_request_invalid';
  end if;

  update public.device_authorizations
  set approved_user_id = p_user_id, approved_at = now()
  where id = v_device.id;

  insert into public.audit_events(user_id, event_type, metadata)
  values (p_user_id, 'device.approved', jsonb_build_object('deviceName', v_device.device_name));

  return jsonb_build_object('deviceName', v_device.device_name);
end;
$$;

create or replace function public.paxinbot_device_poll_v2(
  p_request_id uuid,
  p_secret_hash text
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_device public.device_authorizations%rowtype;
  v_access record;
  v_token text;
  v_expires timestamptz;
begin
  select * into v_device
  from public.device_authorizations
  where id = p_request_id
  for update;

  if not found or p_secret_hash is null
     or not (p_secret_hash = v_device.secret_hash) then
    raise exception 'device_request_invalid';
  end if;
  if v_device.expires_at <= now() then raise exception 'device_expired'; end if;
  if v_device.denied_at is not null then raise exception 'device_denied'; end if;
  if v_device.consumed_at is not null then raise exception 'device_consumed'; end if;

  if v_device.last_polled_at is not null and v_device.last_polled_at > now() - interval '5 seconds' then
    update public.device_authorizations
    set poll_count = poll_count + 1
    where id = v_device.id;
    return jsonb_build_object('status', 'slow_down', 'intervalMs', 10000);
  end if;

  update public.device_authorizations
  set last_polled_at = now(), poll_count = poll_count + 1
  where id = v_device.id;

  if v_device.poll_count >= 180 then raise exception 'device_poll_limit'; end if;
  if v_device.approved_user_id is null then
    return jsonb_build_object('status', 'pending', 'intervalMs', 5000);
  end if;

  select * into v_access
  from public.paxinbot_active_entitlement(v_device.approved_user_id);
  if not found then raise exception 'no_active_access'; end if;

  v_token := encode(extensions.gen_random_bytes(32), 'hex');
  v_expires := now() + interval '7 days';
  insert into public.desktop_sessions
    (token_hash, user_id, device_name, app_version, expires_at)
  values
    (encode(extensions.digest(v_token, 'sha256'), 'hex'), v_device.approved_user_id,
     v_device.device_name, v_device.app_version, v_expires);

  update public.device_authorizations set consumed_at = now() where id = v_device.id;
  insert into public.audit_events(user_id, event_type, metadata)
  values (v_device.approved_user_id, 'device.signed_in',
    jsonb_build_object('deviceName', v_device.device_name, 'appVersion', v_device.app_version));

  return jsonb_build_object(
    'status', 'approved',
    'desktopToken', v_token,
    'sessionExpiresAt', v_expires,
    'entitlement', jsonb_build_object(
      'active', true,
      'kind', v_access.kind,
      'expiresAt', v_access.expires_at,
      'source', v_access.source
    )
  );
end;
$$;

create or replace function public.paxinbot_desktop_session_v2(p_token_hash text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_session public.desktop_sessions%rowtype;
  v_access record;
  v_email text;
begin
  if p_token_hash !~ '^[a-f0-9]{64}$' then raise exception 'desktop_session_invalid'; end if;

  select * into v_session
  from public.desktop_sessions
  where token_hash = p_token_hash
  for update;

  if not found or v_session.revoked_at is not null or v_session.expires_at <= now() then
    raise exception 'desktop_session_invalid';
  end if;

  select * into v_access from public.paxinbot_active_entitlement(v_session.user_id);
  if not found then
    update public.desktop_sessions set revoked_at = now() where id = v_session.id;
    raise exception 'no_active_access';
  end if;

  select email into v_email from auth.users where id = v_session.user_id;
  update public.desktop_sessions set last_seen_at = now() where id = v_session.id;

  return jsonb_build_object(
    'user', jsonb_build_object('id', v_session.user_id, 'email', v_email),
    'deviceName', v_session.device_name,
    'sessionExpiresAt', v_session.expires_at,
    'entitlement', jsonb_build_object(
      'active', true,
      'kind', v_access.kind,
      'expiresAt', v_access.expires_at,
      'source', v_access.source
    )
  );
end;
$$;

-- Remove o caminho antigo que permitia chamar os RPCs diretamente com a
-- chave pública do projeto. A Vercel passa a ser a única fronteira pública.
revoke all on function public.paxinbot_device_start(uuid,text,text,text,text) from public, anon, authenticated;
revoke all on function public.paxinbot_device_approve(uuid,text) from public, anon, authenticated;
revoke all on function public.paxinbot_device_poll(uuid,text) from public, anon, authenticated;
revoke all on function public.paxinbot_desktop_session(text) from public, anon, authenticated;

revoke all on function public.paxinbot_service_rate_limit(text,text,integer,integer) from public, anon, authenticated;
revoke all on function public.paxinbot_device_start_v2(uuid,text,text,text,text) from public, anon, authenticated;
revoke all on function public.paxinbot_device_approve_v2(uuid,text,uuid) from public, anon, authenticated;
revoke all on function public.paxinbot_device_poll_v2(uuid,text) from public, anon, authenticated;
revoke all on function public.paxinbot_desktop_session_v2(text) from public, anon, authenticated;

grant execute on function public.paxinbot_service_rate_limit(text,text,integer,integer) to service_role;
grant execute on function public.paxinbot_device_start_v2(uuid,text,text,text,text) to service_role;
grant execute on function public.paxinbot_device_approve_v2(uuid,text,uuid) to service_role;
grant execute on function public.paxinbot_device_poll_v2(uuid,text) to service_role;
grant execute on function public.paxinbot_desktop_session_v2(text) to service_role;
