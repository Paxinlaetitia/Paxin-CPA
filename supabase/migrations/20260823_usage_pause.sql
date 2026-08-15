-- Pausa confiável do saldo de uso quando o aplicativo é encerrado.
-- O último intervalo efetivamente usado é consolidado no fechamento e o
-- período offline deixa de ser descontado na abertura seguinte.

alter table public.desktop_sessions
  add column if not exists usage_paused_at timestamptz;

create or replace function public.paxinbot_pause_desktop_usage(p_token_hash text)
returns jsonb language plpgsql security definer set search_path = public as $$
declare
  v_session public.desktop_sessions%rowtype;
  v_grant public.usage_grants%rowtype;
  v_elapsed integer := 0;
begin
  if auth.role() <> 'service_role' then raise exception 'service_role_required'; end if;
  if p_token_hash !~ '^[a-f0-9]{64}$' then raise exception 'desktop_session_invalid'; end if;

  select * into v_session from public.desktop_sessions
    where token_hash = p_token_hash for update;
  if not found or v_session.revoked_at is not null or v_session.expires_at <= now() then
    raise exception 'desktop_session_invalid';
  end if;

  if v_session.usage_grant_id is null then
    update public.desktop_sessions set last_seen_at = now() where id = v_session.id;
    return jsonb_build_object('active', true, 'paused', false);
  end if;

  select * into v_grant from public.usage_grants
    where id = v_session.usage_grant_id for update;
  if not found or v_grant.status <> 'active' or v_grant.remaining_seconds <= 0 then
    return jsonb_build_object('active', false, 'reason', 'usage_unavailable');
  end if;

  -- Repetições do evento de fechamento são idempotentes.
  if v_session.usage_paused_at is not null then
    return jsonb_build_object('active', true, 'paused', true,
      'remainingSeconds', v_grant.remaining_seconds);
  end if;

  if v_session.last_seen_at >= now() - interval '60 seconds' then
    v_elapsed := least(15, greatest(0,
      floor(extract(epoch from (now() - v_session.last_seen_at)))::integer));
  end if;

  if v_elapsed >= v_grant.remaining_seconds then
    update public.usage_grants set remaining_seconds = 0, status = 'exhausted', updated_at = now()
      where id = v_grant.id returning * into v_grant;
    update public.desktop_sessions set revoked_at = now(), last_seen_at = now(), usage_paused_at = now()
      where usage_grant_id = v_grant.id and revoked_at is null;
    return jsonb_build_object('active', false, 'reason', 'usage_exhausted');
  end if;

  update public.usage_grants
    set remaining_seconds = remaining_seconds - v_elapsed, updated_at = now()
    where id = v_grant.id returning * into v_grant;
  update public.desktop_sessions
    set last_seen_at = now(), usage_paused_at = now()
    where id = v_session.id;

  return jsonb_build_object('active', true, 'paused', true,
    'remainingSeconds', v_grant.remaining_seconds);
end;
$$;

create or replace function public.paxinbot_desktop_session_v2(p_token_hash text)
returns jsonb language plpgsql security definer set search_path = public as $$
declare
  v_session public.desktop_sessions%rowtype; v_access record; v_grant public.usage_grants%rowtype;
  v_email text; v_elapsed integer:=0;
begin
  if p_token_hash !~ '^[a-f0-9]{64}$' then raise exception 'desktop_session_invalid'; end if;
  select * into v_session from public.desktop_sessions where token_hash=p_token_hash for update;
  if not found or v_session.revoked_at is not null or v_session.expires_at<=now() then raise exception 'desktop_session_invalid'; end if;

  if v_session.usage_grant_id is not null then
    select e.kind,e.expires_at,e.source into v_access
      from public.entitlements e join public.profiles p on p.id=e.user_id
      where e.user_id=v_session.user_id and p.disabled_at is null and e.status='active'
        and e.starts_at<=now() and (e.expires_at is null or e.expires_at>now())
      order by case e.kind when 'lifetime' then 0 else 1 end,e.expires_at desc nulls first limit 1;
    if found then
      select email into v_email from auth.users where id=v_session.user_id;
      update public.desktop_sessions set usage_grant_id=null,usage_paused_at=null,last_seen_at=now() where id=v_session.id;
      return jsonb_build_object('active',true,'user',jsonb_build_object('id',v_session.user_id,'email',v_email),
        'deviceName',v_session.device_name,'sessionExpiresAt',v_session.expires_at,
        'entitlement',jsonb_build_object('active',true,'kind',v_access.kind,'expiresAt',v_access.expires_at,'source',v_access.source));
    end if;

    select * into v_grant from public.usage_grants where id=v_session.usage_grant_id for update;
    if not found or v_grant.status<>'active' or v_grant.remaining_seconds<=0 then
      update public.desktop_sessions set revoked_at=now() where id=v_session.id;
      return jsonb_build_object('active',false,'reason','usage_unavailable');
    end if;

    -- A primeira validação depois de uma pausa apenas reabre a medição.
    if v_session.usage_paused_at is null and v_session.last_seen_at>=now()-interval '60 seconds' then
      v_elapsed:=least(15,greatest(0,floor(extract(epoch from (now()-v_session.last_seen_at)))::integer));
    end if;
    if v_elapsed>=v_grant.remaining_seconds then
      update public.usage_grants set remaining_seconds=0,status='exhausted',updated_at=now() where id=v_grant.id;
      update public.desktop_sessions set revoked_at=now(),last_seen_at=now(),usage_paused_at=null where usage_grant_id=v_grant.id and revoked_at is null;
      insert into public.audit_events(user_id,event_type,metadata)
        values(v_session.user_id,'usage.exhausted',jsonb_build_object('grantId',v_grant.id));
      return jsonb_build_object('active',false,'reason','usage_exhausted');
    end if;
    update public.usage_grants set remaining_seconds=remaining_seconds-v_elapsed,updated_at=now()
      where id=v_grant.id returning * into v_grant;
    update public.desktop_sessions set last_seen_at=now(),usage_paused_at=null where id=v_session.id;
    select email into v_email from auth.users where id=v_session.user_id;
    return jsonb_build_object('active',true,'user',jsonb_build_object('id',v_session.user_id,'email',v_email),
      'deviceName',v_session.device_name,'sessionExpiresAt',v_session.expires_at,
      'entitlement',jsonb_build_object('active',true,'kind','usage','expiresAt',null,'source',v_grant.source,
        'grantId',v_grant.id,'totalSeconds',v_grant.total_seconds,'remainingSeconds',v_grant.remaining_seconds));
  end if;

  select * into v_access from public.paxinbot_active_entitlement(v_session.user_id);
  if not found then
    update public.desktop_sessions set revoked_at=now() where id=v_session.id;
    return jsonb_build_object('active',false,'reason','no_active_access');
  end if;
  select email into v_email from auth.users where id=v_session.user_id;
  update public.desktop_sessions set last_seen_at=now(),usage_paused_at=null where id=v_session.id;
  return jsonb_build_object('active',true,'user',jsonb_build_object('id',v_session.user_id,'email',v_email),
    'deviceName',v_session.device_name,'sessionExpiresAt',v_session.expires_at,
    'entitlement',jsonb_build_object('active',true,'kind',v_access.kind,'expiresAt',v_access.expires_at,'source',v_access.source));
end;
$$;

revoke all on function public.paxinbot_pause_desktop_usage(text) from public;
revoke all on function public.paxinbot_desktop_session_v2(text) from public;
grant execute on function public.paxinbot_pause_desktop_usage(text) to service_role;
grant execute on function public.paxinbot_desktop_session_v2(text) to service_role;
