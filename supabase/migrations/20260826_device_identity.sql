-- Paxinbot: identidade criptográfica do dispositivo, bloqueio por máquina e
-- vínculo do benefício promocional ao primeiro computador autorizado.
-- Execute depois de 20260825_promotions.sql.

create table if not exists public.device_identities (
  id uuid primary key default extensions.gen_random_uuid(),
  install_id_hash text not null check (install_id_hash ~ '^[a-f0-9]{64}$'),
  device_key_hash text not null unique check (device_key_hash ~ '^[a-f0-9]{64}$'),
  fingerprint_hash text not null check (fingerprint_hash ~ '^[a-f0-9]{64}$'),
  public_key text not null check (public_key ~ '^[A-Za-z0-9_-]{50,200}$'),
  fingerprint_strength text not null check (fingerprint_strength in ('hardware','installation')),
  device_name text not null check (char_length(device_name) between 1 and 80),
  first_seen_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  banned_at timestamptz,
  ban_reason text check (ban_reason is null or char_length(ban_reason) between 3 and 200),
  banned_by uuid references auth.users(id) on delete set null
);

create index if not exists device_identities_fingerprint_idx on public.device_identities(fingerprint_hash);
create index if not exists device_identities_last_seen_idx on public.device_identities(last_seen_at desc);
create index if not exists device_identities_banned_idx on public.device_identities(banned_at) where banned_at is not null;
alter table public.device_identities enable row level security;
revoke all on table public.device_identities from public,anon,authenticated;

alter table public.device_authorizations
  add column if not exists device_identity_id uuid references public.device_identities(id) on delete restrict,
  add column if not exists proof_nonce_hash text;
alter table public.desktop_sessions
  add column if not exists device_identity_id uuid references public.device_identities(id) on delete restrict;
create unique index if not exists device_authorizations_proof_nonce_idx
  on public.device_authorizations(proof_nonce_hash) where proof_nonce_hash is not null;
create index if not exists device_authorizations_identity_idx on public.device_authorizations(device_identity_id);
create index if not exists desktop_sessions_identity_idx on public.desktop_sessions(device_identity_id,last_seen_at desc);

create or replace function public.paxinbot_device_start_v3(
  p_request_id uuid,p_secret_hash text,p_user_code text,p_device_name text,p_app_version text,
  p_install_id_hash text,p_device_key_hash text,p_fingerprint_hash text,p_public_key text,
  p_fingerprint_strength text,p_proof_nonce_hash text
)
returns jsonb language plpgsql security definer set search_path=public,auth,pg_temp as $$
declare v_identity public.device_identities%rowtype; v_result jsonb;
begin
  if auth.role()<>'service_role' then raise exception 'service_role_required'; end if;
  if p_install_id_hash !~ '^[a-f0-9]{64}$' or p_device_key_hash !~ '^[a-f0-9]{64}$'
    or p_fingerprint_hash !~ '^[a-f0-9]{64}$' or p_proof_nonce_hash !~ '^[a-f0-9]{64}$'
    or p_public_key !~ '^[A-Za-z0-9_-]{50,200}$' or p_fingerprint_strength not in ('hardware','installation') then
    raise exception 'device_identity_invalid';
  end if;
  if exists(select 1 from public.device_authorizations where proof_nonce_hash=p_proof_nonce_hash) then
    raise exception 'device_proof_replayed';
  end if;
  if exists(select 1 from public.device_identities where fingerprint_hash=p_fingerprint_hash and banned_at is not null) then
    raise exception 'device_banned';
  end if;

  select * into v_identity from public.device_identities where device_key_hash=p_device_key_hash for update;
  if found then
    if v_identity.fingerprint_hash<>p_fingerprint_hash or v_identity.install_id_hash<>p_install_id_hash
      or v_identity.public_key<>p_public_key then raise exception 'device_identity_mismatch'; end if;
    if v_identity.banned_at is not null then raise exception 'device_banned'; end if;
    update public.device_identities set last_seen_at=now(),device_name=trim(p_device_name),
      fingerprint_strength=p_fingerprint_strength where id=v_identity.id returning * into v_identity;
  else
    if exists(select 1 from public.device_identities where install_id_hash=p_install_id_hash) then
      raise exception 'device_identity_mismatch';
    end if;
    insert into public.device_identities(install_id_hash,device_key_hash,fingerprint_hash,public_key,fingerprint_strength,device_name)
      values(p_install_id_hash,p_device_key_hash,p_fingerprint_hash,p_public_key,p_fingerprint_strength,trim(p_device_name))
      returning * into v_identity;
  end if;

  v_result:=public.paxinbot_device_start_v2(p_request_id,p_secret_hash,p_user_code,p_device_name,p_app_version);
  update public.device_authorizations set device_identity_id=v_identity.id,proof_nonce_hash=p_proof_nonce_hash
    where id=p_request_id;
  return v_result;
end;
$$;

create or replace function public.paxinbot_device_approve_v3(p_request_id uuid,p_user_code text,p_user_id uuid)
returns jsonb language plpgsql security definer set search_path=public,auth,pg_temp as $$
declare v_identity_id uuid;
begin
  if auth.role()<>'service_role' then raise exception 'service_role_required'; end if;
  select device_identity_id into v_identity_id from public.device_authorizations where id=p_request_id;
  if v_identity_id is null then raise exception 'device_identity_invalid'; end if;
  if exists(select 1 from public.device_identities d where d.id=v_identity_id and d.banned_at is not null)
    or exists(select 1 from public.device_identities source join public.device_identities banned
      on banned.fingerprint_hash=source.fingerprint_hash and banned.banned_at is not null where source.id=v_identity_id) then
    raise exception 'device_banned';
  end if;
  return public.paxinbot_device_approve_v2(p_request_id,p_user_code,p_user_id);
end;
$$;

create or replace function public.paxinbot_device_poll_v3(p_request_id uuid,p_secret_hash text)
returns jsonb language plpgsql security definer set search_path=public,auth,pg_temp as $$
declare
  v_device public.device_authorizations%rowtype; v_identity public.device_identities%rowtype;
  v_claim public.promotion_claims%rowtype; v_result jsonb; v_token_hash text;
begin
  if auth.role()<>'service_role' then raise exception 'service_role_required'; end if;
  select * into v_device from public.device_authorizations where id=p_request_id for update;
  if not found or v_device.device_identity_id is null then raise exception 'device_request_invalid'; end if;
  select * into v_identity from public.device_identities where id=v_device.device_identity_id for update;
  if not found or v_identity.banned_at is not null
    or exists(select 1 from public.device_identities where fingerprint_hash=v_identity.fingerprint_hash and banned_at is not null) then
    raise exception 'device_banned';
  end if;

  if v_device.approved_user_id is not null then
    select pc.* into v_claim from public.promotion_claims pc
      join public.usage_grants ug on ug.id=pc.usage_grant_id
      where ug.user_id=v_device.approved_user_id and ug.status='active'
      order by ug.activated_at desc nulls last,ug.created_at desc limit 1 for update of pc;
    if found then
      if v_claim.device_fingerprint_hash is not null and v_claim.device_fingerprint_hash<>v_identity.fingerprint_hash then
        raise exception 'promotion_device_already_used';
      end if;
      if exists(select 1 from public.promotion_claims other where other.promotion_id=v_claim.promotion_id
        and other.device_fingerprint_hash=v_identity.fingerprint_hash and other.id<>v_claim.id) then
        raise exception 'promotion_device_already_used';
      end if;
      update public.promotion_claims set device_fingerprint_hash=v_identity.fingerprint_hash where id=v_claim.id;
    end if;
  end if;

  v_result:=public.paxinbot_device_poll_v2(p_request_id,p_secret_hash);
  if v_result->>'status'='approved' then
    v_token_hash:=encode(extensions.digest(v_result->>'desktopToken','sha256'),'hex');
    update public.desktop_sessions set device_identity_id=v_identity.id where token_hash=v_token_hash;
  end if;
  update public.device_identities set last_seen_at=now() where id=v_identity.id;
  return v_result;
end;
$$;

create or replace function public.paxinbot_desktop_session_v3(p_token_hash text)
returns jsonb language plpgsql security definer set search_path=public,auth,pg_temp as $$
declare v_session public.desktop_sessions%rowtype; v_identity public.device_identities%rowtype; v_result jsonb;
begin
  if auth.role()<>'service_role' then raise exception 'service_role_required'; end if;
  select * into v_session from public.desktop_sessions where token_hash=p_token_hash for update;
  if not found or v_session.device_identity_id is null then raise exception 'desktop_session_invalid'; end if;
  select * into v_identity from public.device_identities where id=v_session.device_identity_id for update;
  if not found or v_identity.banned_at is not null
    or exists(select 1 from public.device_identities where fingerprint_hash=v_identity.fingerprint_hash and banned_at is not null) then
    update public.desktop_sessions set revoked_at=coalesce(revoked_at,now()) where id=v_session.id;
    return jsonb_build_object('active',false,'reason','device_banned');
  end if;
  v_result:=public.paxinbot_desktop_session_v2(p_token_hash);
  update public.device_identities set last_seen_at=now() where id=v_identity.id;
  return v_result;
end;
$$;

create or replace function public.paxinbot_pause_desktop_usage_v3(p_token_hash text)
returns jsonb language plpgsql security definer set search_path=public,auth,pg_temp as $$
declare v_session public.desktop_sessions%rowtype; v_identity public.device_identities%rowtype;
begin
  if auth.role()<>'service_role' then raise exception 'service_role_required'; end if;
  select * into v_session from public.desktop_sessions where token_hash=p_token_hash for update;
  if not found or v_session.device_identity_id is null then raise exception 'desktop_session_invalid'; end if;
  select * into v_identity from public.device_identities where id=v_session.device_identity_id;
  if not found or v_identity.banned_at is not null
    or exists(select 1 from public.device_identities where fingerprint_hash=v_identity.fingerprint_hash and banned_at is not null) then
    update public.desktop_sessions set revoked_at=coalesce(revoked_at,now()) where id=v_session.id;
    return jsonb_build_object('active',false,'reason','device_banned');
  end if;
  return public.paxinbot_pause_desktop_usage(p_token_hash);
end;
$$;

create or replace function public.paxinbot_owner_list_device_identities(p_query text default '')
returns jsonb language plpgsql stable security definer set search_path=public,auth,pg_temp as $$
declare v_query text:=lower(trim(coalesce(p_query,'')));
begin
  perform public.paxinbot_require_owner();
  return coalesce((select jsonb_agg(row_to_json(x) order by x.last_seen_at desc) from (
    select d.id,d.device_name,d.fingerprint_strength,d.first_seen_at,d.last_seen_at,
      d.banned_at,d.ban_reason,
      coalesce((select string_agg(distinct lower(u.email),', ' order by lower(u.email))
        from public.desktop_sessions ds join auth.users u on u.id=ds.user_id where ds.device_identity_id=d.id),'') as accounts
    from public.device_identities d
    where v_query='' or lower(d.device_name) like '%'||v_query||'%'
      or exists(select 1 from public.desktop_sessions ds join auth.users u on u.id=ds.user_id
        where ds.device_identity_id=d.id and lower(u.email) like '%'||v_query||'%')
  ) x),'[]'::jsonb);
end;
$$;

create or replace function public.paxinbot_owner_set_device_ban(p_device_identity_id uuid,p_banned boolean,p_reason text default null)
returns jsonb language plpgsql security definer set search_path=public,auth,pg_temp as $$
declare v_identity public.device_identities%rowtype; v_reason text:=nullif(trim(coalesce(p_reason,'')),''); v_count integer;
begin
  perform public.paxinbot_require_owner();
  select * into v_identity from public.device_identities where id=p_device_identity_id for update;
  if not found then raise exception 'device_identity_not_found'; end if;
  if coalesce(p_banned,false) and (v_reason is null or char_length(v_reason) not between 3 and 200) then
    raise exception 'invalid_ban_reason';
  end if;

  update public.device_identities set banned_at=case when coalesce(p_banned,false) then now() else null end,
    ban_reason=case when coalesce(p_banned,false) then v_reason else null end,
    banned_by=case when coalesce(p_banned,false) then auth.uid() else null end
    where fingerprint_hash=v_identity.fingerprint_hash;
  get diagnostics v_count=row_count;
  if coalesce(p_banned,false) then
    update public.desktop_sessions set revoked_at=coalesce(revoked_at,now())
      where device_identity_id in (select id from public.device_identities where fingerprint_hash=v_identity.fingerprint_hash);
    update public.device_authorizations set denied_at=coalesce(denied_at,now())
      where consumed_at is null and device_identity_id in (select id from public.device_identities where fingerprint_hash=v_identity.fingerprint_hash);
  end if;
  insert into public.audit_events(user_id,event_type,metadata) values(auth.uid(),
    case when coalesce(p_banned,false) then 'owner.device_banned' else 'owner.device_unbanned' end,
    jsonb_build_object('deviceIdentityId',p_device_identity_id,'affectedIdentities',v_count,'reason',v_reason));
  return jsonb_build_object('ok',true,'affectedIdentities',v_count,'banned',coalesce(p_banned,false));
end;
$$;

revoke all on function public.paxinbot_device_start_v3(uuid,text,text,text,text,text,text,text,text,text,text) from public,anon,authenticated;
revoke all on function public.paxinbot_device_approve_v3(uuid,text,uuid) from public,anon,authenticated;
revoke all on function public.paxinbot_device_poll_v3(uuid,text) from public,anon,authenticated;
revoke all on function public.paxinbot_desktop_session_v3(text) from public,anon,authenticated;
revoke all on function public.paxinbot_pause_desktop_usage_v3(text) from public,anon,authenticated;
revoke all on function public.paxinbot_owner_list_device_identities(text) from public;
revoke all on function public.paxinbot_owner_set_device_ban(uuid,boolean,text) from public;
grant execute on function public.paxinbot_device_start_v3(uuid,text,text,text,text,text,text,text,text,text,text) to service_role;
grant execute on function public.paxinbot_device_approve_v3(uuid,text,uuid) to service_role;
grant execute on function public.paxinbot_device_poll_v3(uuid,text) to service_role;
grant execute on function public.paxinbot_desktop_session_v3(text) to service_role;
grant execute on function public.paxinbot_pause_desktop_usage_v3(text) to service_role;
grant execute on function public.paxinbot_owner_list_device_identities(text) to authenticated;
grant execute on function public.paxinbot_owner_set_device_ban(uuid,boolean,text) to authenticated;
