-- Corrige a resolução das funções do pgcrypto no fluxo de sessão desktop.
-- No Supabase, pgcrypto é instalado no schema `extensions`; como as funções
-- de autenticação usam um search_path restrito, as chamadas devem ser
-- totalmente qualificadas.

create extension if not exists pgcrypto with schema extensions;

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
  if p_secret_hash !~ '^[a-f0-9]{64}$' then raise exception 'invalid_device_request'; end if;

  select * into v_device
  from public.device_authorizations
  where id = p_request_id and secret_hash = p_secret_hash
  for update;

  if not found then raise exception 'device_request_invalid'; end if;
  if v_device.expires_at <= now() then raise exception 'device_expired'; end if;
  if v_device.consumed_at is not null then raise exception 'device_consumed'; end if;
  if v_device.denied_at is not null then raise exception 'device_denied'; end if;
  if v_device.last_polled_at is not null and v_device.last_polled_at > now() - interval '2 seconds' then
    raise exception 'device_poll_limit';
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

revoke all on function public.paxinbot_device_poll_v2(uuid,text) from public, anon, authenticated;
grant execute on function public.paxinbot_device_poll_v2(uuid,text) to service_role;
