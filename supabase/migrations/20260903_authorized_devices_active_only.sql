-- Paxinbot: a lista de computadores autorizados contém somente acessos ativos.
-- Sessões revogadas ou expiradas permanecem preservadas para auditoria.
-- Execute depois de 20260902_device_portal_identity_dedup.sql.

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
        row_number() over (
          partition by coalesce(d.fingerprint_hash, 'legacy:' || s.id::text)
          order by s.last_seen_at desc, s.created_at desc
        ) as recent_rank
      from public.desktop_sessions s
      left join public.device_identities d on d.id=s.device_identity_id
      where s.user_id=auth.uid()
        and s.revoked_at is null
        and s.expires_at > now()
    ), grouped as (
      select
        min(coalesce(s.device_identity_id, s.id)::text)::uuid as id,
        max(s.device_name) filter (where s.recent_rank=1) as device_name,
        min(s.created_at) as created_at,
        max(s.last_seen_at) as last_seen_at,
        max(s.expires_at) as expires_at,
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
      'status', 'active'
    ) order by g.last_seen_at desc)
    from grouped g
  ), '[]'::jsonb);
end;
$$;
