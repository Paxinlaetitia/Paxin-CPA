-- Paxinbot: apresenta uma máquina por HWID verificado na Área do Cliente.
-- As sessões continuam individuais para rotação de token e auditoria.
-- Execute depois de 20260901_portal_performance.sql.

create or replace function public.paxinbot_list_my_devices()
returns jsonb language plpgsql stable security definer
set search_path=public,auth,pg_temp as $$
begin
  if auth.uid() is null then raise exception 'not_authenticated'; end if;

  return coalesce((
    with session_rows as (
      select
        s.*,
        d.fingerprint_hash,
        coalesce(d.fingerprint_hash, 'legacy:' || s.id::text) as device_group,
        row_number() over (
          partition by coalesce(d.fingerprint_hash, 'legacy:' || s.id::text)
          order by s.last_seen_at desc, s.created_at desc
        ) as recent_rank
      from public.desktop_sessions s
      left join public.device_identities d on d.id=s.device_identity_id
      where s.user_id=auth.uid()
    ), grouped as (
      select
        min(coalesce(s.device_identity_id, s.id)::text)::uuid as id,
        max(s.device_name) filter (where s.recent_rank=1) as device_name,
        min(s.created_at) as created_at,
        max(s.last_seen_at) as last_seen_at,
        coalesce(
          max(s.expires_at) filter (where s.revoked_at is null and s.expires_at > now()),
          max(s.expires_at)
        ) as expires_at,
        bool_or(s.revoked_at is null and s.expires_at > now()) as has_active,
        bool_or(s.revoked_at is not null) as has_revoked,
        count(*)::integer as session_count
      from session_rows s
      group by coalesce(s.fingerprint_hash, 'legacy:' || s.id::text)
      order by max(s.last_seen_at) desc
      limit 50
    )
    select jsonb_agg(jsonb_build_object(
      'id', g.id,
      'deviceName', g.device_name,
      'createdAt', g.created_at,
      'lastSeenAt', g.last_seen_at,
      'expiresAt', g.expires_at,
      'sessionCount', g.session_count,
      'status', case when g.has_active then 'active' when g.has_revoked then 'revoked' else 'expired' end
    ) order by g.last_seen_at desc)
    from grouped g
  ), '[]'::jsonb);
end;
$$;

create or replace function public.paxinbot_revoke_my_device(p_session_id uuid)
returns void language plpgsql security definer
set search_path=public,auth,pg_temp as $$
declare
  v_fingerprint_hash text;
  v_count integer := 0;
  v_legacy boolean := false;
begin
  if auth.uid() is null then raise exception 'not_authenticated'; end if;

  select d.fingerprint_hash into v_fingerprint_hash
  from public.device_identities d
  where d.id=p_session_id
    and exists (
      select 1 from public.desktop_sessions owned
      where owned.user_id=auth.uid() and owned.device_identity_id=d.id
    );

  if found then
    update public.desktop_sessions s
    set revoked_at=coalesce(s.revoked_at, now())
    where s.user_id=auth.uid()
      and s.device_identity_id in (
        select identity_row.id
        from public.device_identities identity_row
        where identity_row.fingerprint_hash=v_fingerprint_hash
      );
    get diagnostics v_count=row_count;
  else
    -- Compatibilidade com sessões criadas antes da identidade criptográfica.
    v_legacy := true;
    update public.desktop_sessions s
    set revoked_at=coalesce(s.revoked_at, now())
    where s.id=p_session_id and s.user_id=auth.uid() and s.device_identity_id is null;
    get diagnostics v_count=row_count;
  end if;

  if v_count=0 then raise exception 'device_not_found'; end if;

  insert into public.audit_events (user_id,event_type,metadata)
  values (
    auth.uid(),
    'device.revoked',
    jsonb_build_object('deviceIdentityId',p_session_id,'sessionsRevoked',v_count,'legacy',v_legacy)
  );
end;
$$;
