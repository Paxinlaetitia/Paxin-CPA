-- Paxinbot: telemetria antifraude minimizada e resposta graduada.
-- Execute depois de 20260826_device_identity.sql.
--
-- Privacidade: esta estrutura aceita somente tipos e campos enumerados. Ela
-- não armazena URLs, histórico de navegação, texto digitado, capturas de tela,
-- senhas, tokens ou identificadores brutos do computador.

create table if not exists public.security_events (
  id uuid primary key default extensions.gen_random_uuid(),
  event_id uuid not null unique,
  occurred_at timestamptz not null,
  received_at timestamptz not null default now(),
  user_id uuid references auth.users(id) on delete set null,
  device_identity_id uuid references public.device_identities(id) on delete set null,
  desktop_session_id uuid references public.desktop_sessions(id) on delete set null,
  event_type text not null check (event_type in (
    'integrity_failure','release_rollback_blocked','debug_flag_detected',
    'device_identity_mismatch','device_proof_replayed','auth_rate_limited',
    'session_rejected','update_signature_failure','runtime_contract_failure'
  )),
  severity smallint not null check (severity between 0 and 100),
  source text not null default 'desktop' check (source in ('desktop','server')),
  app_version text not null check (app_version ~ '^\d{1,4}(\.\d{1,4}){1,3}(-[0-9A-Za-z.-]{1,24})?$'),
  release_sequence integer check (release_sequence is null or release_sequence between 1 and 2147483647),
  details jsonb not null default '{}'::jsonb check (jsonb_typeof(details)='object' and octet_length(details::text)<=1024)
);

create index if not exists security_events_device_idx on public.security_events(device_identity_id,received_at desc);
create index if not exists security_events_user_idx on public.security_events(user_id,received_at desc);
create index if not exists security_events_type_idx on public.security_events(event_type,received_at desc);
alter table public.security_events enable row level security;
revoke all on table public.security_events from public,anon,authenticated;

create table if not exists public.security_risk_state (
  device_identity_id uuid primary key references public.device_identities(id) on delete cascade,
  score smallint not null default 0 check (score between 0 and 100),
  level text not null default 'normal' check (level in ('normal','watch','restricted')),
  last_event_type text,
  last_event_at timestamptz,
  restricted_until timestamptz,
  reviewed_at timestamptz,
  reviewed_by uuid references auth.users(id) on delete set null,
  updated_at timestamptz not null default now()
);

create index if not exists security_risk_state_level_idx on public.security_risk_state(level,score desc,updated_at desc);
alter table public.security_risk_state enable row level security;
revoke all on table public.security_risk_state from public,anon,authenticated;

create or replace function public.paxinbot_record_security_event(
  p_token_hash text,
  p_event_id uuid,
  p_event_type text,
  p_occurred_at timestamptz,
  p_app_version text,
  p_release_sequence integer,
  p_details jsonb default '{}'::jsonb
)
returns jsonb language plpgsql security definer set search_path=public,auth,pg_temp as $$
declare
  v_session public.desktop_sessions%rowtype;
  v_state public.security_risk_state%rowtype;
  v_weight integer;
  v_decay integer:=0;
  v_score integer;
  v_level text;
  v_inserted integer:=0;
  v_restricted_until timestamptz;
begin
  if auth.role()<>'service_role' then raise exception 'service_role_required'; end if;
  if p_token_hash !~ '^[a-f0-9]{64}$' or p_event_id is null then raise exception 'security_event_invalid'; end if;
  if p_event_type not in (
    'integrity_failure','release_rollback_blocked','debug_flag_detected',
    'device_identity_mismatch','device_proof_replayed','auth_rate_limited',
    'session_rejected','update_signature_failure','runtime_contract_failure'
  ) then raise exception 'security_event_invalid'; end if;
  if p_occurred_at is null or p_occurred_at < now()-interval '7 days' or p_occurred_at > now()+interval '10 minutes'
    or p_app_version !~ '^\d{1,4}(\.\d{1,4}){1,3}(-[0-9A-Za-z.-]{1,24})?$'
    or p_release_sequence not between 1 and 2147483647 then raise exception 'security_event_invalid'; end if;
  if jsonb_typeof(coalesce(p_details,'{}'::jsonb))<>'object' or octet_length(coalesce(p_details,'{}'::jsonb)::text)>1024
    or exists(select 1 from jsonb_object_keys(coalesce(p_details,'{}'::jsonb)) as key
      where key not in ('reasonCode','component','operation','outcome')) then raise exception 'security_event_details_invalid'; end if;
  if exists(select 1 from jsonb_each_text(coalesce(p_details,'{}'::jsonb)) entry
    where entry.value !~ '^[A-Za-z0-9_.:-]{1,80}$') then raise exception 'security_event_details_invalid'; end if;

  select * into v_session from public.desktop_sessions where token_hash=p_token_hash for update;
  if not found or v_session.device_identity_id is null then raise exception 'desktop_session_invalid'; end if;

  v_weight:=case p_event_type
    when 'integrity_failure' then 90
    when 'release_rollback_blocked' then 90
    when 'device_proof_replayed' then 85
    when 'update_signature_failure' then 80
    when 'device_identity_mismatch' then 70
    when 'runtime_contract_failure' then 70
    when 'debug_flag_detected' then 65
    when 'auth_rate_limited' then 15
    when 'session_rejected' then 10
    else 0 end;

  insert into public.security_events(event_id,occurred_at,user_id,device_identity_id,desktop_session_id,
    event_type,severity,source,app_version,release_sequence,details)
  values(p_event_id,p_occurred_at,v_session.user_id,v_session.device_identity_id,v_session.id,
    p_event_type,v_weight,'desktop',p_app_version,p_release_sequence,coalesce(p_details,'{}'::jsonb))
  on conflict(event_id) do nothing;
  get diagnostics v_inserted=row_count;

  select * into v_state from public.security_risk_state where device_identity_id=v_session.device_identity_id for update;
  if v_inserted=0 then
    return jsonb_build_object('ok',true,'duplicate',true,'action',
      case when found and v_state.restricted_until>now() then 'reauthenticate' else 'allow' end);
  end if;

  if found then
    v_decay:=greatest(0,floor(extract(epoch from (now()-v_state.updated_at))/3600)::integer*2);
    v_score:=least(100,greatest(0,v_state.score-v_decay)+v_weight);
  else
    v_score:=least(100,v_weight);
  end if;
  v_level:=case when v_score>=70 then 'restricted' when v_score>=40 then 'watch' else 'normal' end;
  v_restricted_until:=case when v_score>=70 then greatest(coalesce(v_state.restricted_until,now()),now()+interval '15 minutes') else v_state.restricted_until end;

  insert into public.security_risk_state(device_identity_id,score,level,last_event_type,last_event_at,restricted_until,updated_at)
  values(v_session.device_identity_id,v_score,v_level,p_event_type,p_occurred_at,v_restricted_until,now())
  on conflict(device_identity_id) do update set score=excluded.score,level=excluded.level,
    last_event_type=excluded.last_event_type,last_event_at=excluded.last_event_at,
    restricted_until=excluded.restricted_until,updated_at=now();

  if v_score>=70 then
    update public.desktop_sessions set revoked_at=coalesce(revoked_at,now()) where id=v_session.id;
  end if;
  if v_score>=90 then
    update public.desktop_sessions set revoked_at=coalesce(revoked_at,now())
      where device_identity_id=v_session.device_identity_id and revoked_at is null;
    update public.device_authorizations set denied_at=coalesce(denied_at,now())
      where device_identity_id=v_session.device_identity_id and consumed_at is null;
  end if;

  return jsonb_build_object('ok',true,'duplicate',false,'action',case when v_score>=70 then 'reauthenticate' else 'allow' end,
    'level',v_level);
end;
$$;

-- Falhas detectadas antes de existir uma sessão são correlacionadas somente
-- pelos hashes opacos já produzidos no servidor. Se a identidade ainda não
-- existe, o evento é descartado em vez de criar um perfil rastreável.
create or replace function public.paxinbot_record_device_security_event(
  p_device_key_hash text,p_fingerprint_hash text,p_event_id uuid,p_event_type text,p_app_version text
)
returns jsonb language plpgsql security definer set search_path=public,auth,pg_temp as $$
declare v_identity public.device_identities%rowtype; v_state public.security_risk_state%rowtype;
  v_weight integer; v_score integer; v_decay integer:=0; v_level text; v_inserted integer:=0; v_restricted_until timestamptz;
begin
  if auth.role()<>'service_role' then raise exception 'service_role_required'; end if;
  if p_device_key_hash !~ '^[a-f0-9]{64}$' or p_fingerprint_hash !~ '^[a-f0-9]{64}$' or p_event_id is null
    or p_event_type not in ('device_identity_mismatch','device_proof_replayed','auth_rate_limited')
    or p_app_version !~ '^\d{1,4}(\.\d{1,4}){1,3}(-[0-9A-Za-z.-]{1,24})?$' then raise exception 'security_event_invalid'; end if;
  select * into v_identity from public.device_identities
    where device_key_hash=p_device_key_hash or fingerprint_hash=p_fingerprint_hash
    order by (device_key_hash=p_device_key_hash) desc,last_seen_at desc limit 1 for update;
  if not found then return jsonb_build_object('ok',true,'ignored',true); end if;
  v_weight:=case p_event_type when 'device_proof_replayed' then 85 when 'device_identity_mismatch' then 70 else 15 end;
  insert into public.security_events(event_id,occurred_at,user_id,device_identity_id,event_type,severity,source,app_version,release_sequence,details)
    values(p_event_id,now(),null,v_identity.id,p_event_type,v_weight,'server',p_app_version,null,'{}'::jsonb)
    on conflict(event_id) do nothing;
  get diagnostics v_inserted=row_count;
  if v_inserted=0 then return jsonb_build_object('ok',true,'duplicate',true); end if;
  select * into v_state from public.security_risk_state where device_identity_id=v_identity.id for update;
  if found then
    v_decay:=greatest(0,floor(extract(epoch from (now()-v_state.updated_at))/3600)::integer*2);
    v_score:=least(100,greatest(0,v_state.score-v_decay)+v_weight);
  else v_score:=least(100,v_weight); end if;
  v_level:=case when v_score>=70 then 'restricted' when v_score>=40 then 'watch' else 'normal' end;
  v_restricted_until:=case when v_score>=70 then greatest(coalesce(v_state.restricted_until,now()),now()+interval '15 minutes') else v_state.restricted_until end;
  insert into public.security_risk_state(device_identity_id,score,level,last_event_type,last_event_at,restricted_until,updated_at)
    values(v_identity.id,v_score,v_level,p_event_type,now(),v_restricted_until,now())
    on conflict(device_identity_id) do update set score=excluded.score,level=excluded.level,last_event_type=excluded.last_event_type,
      last_event_at=excluded.last_event_at,restricted_until=excluded.restricted_until,updated_at=now();
  if v_score>=70 then update public.desktop_sessions set revoked_at=coalesce(revoked_at,now()) where device_identity_id=v_identity.id and revoked_at is null; end if;
  if v_score>=90 then update public.device_authorizations set denied_at=coalesce(denied_at,now()) where device_identity_id=v_identity.id and consumed_at is null; end if;
  return jsonb_build_object('ok',true,'action',case when v_score>=70 then 'reauthenticate' else 'allow' end,'level',v_level);
end;
$$;

create or replace function public.paxinbot_owner_list_security_risk(p_query text default '')
returns jsonb language plpgsql stable security definer set search_path=public,auth,pg_temp as $$
declare v_query text:=lower(trim(coalesce(p_query,'')));
begin
  perform public.paxinbot_require_owner();
  return coalesce((select jsonb_agg(row_to_json(x) order by x.score desc,x.last_event_at desc nulls last) from (
    select d.id,d.device_name,coalesce(r.score,0) as score,coalesce(r.level,'normal') as level,
      r.last_event_type,r.last_event_at,r.restricted_until,r.reviewed_at,
      (select count(*) from public.security_events e where e.device_identity_id=d.id) as event_count,
      coalesce((select string_agg(distinct lower(u.email),', ' order by lower(u.email))
        from public.desktop_sessions ds join auth.users u on u.id=ds.user_id where ds.device_identity_id=d.id),'') as accounts
    from public.device_identities d left join public.security_risk_state r on r.device_identity_id=d.id
    where r.device_identity_id is not null and (v_query='' or lower(d.device_name) like '%'||v_query||'%'
      or exists(select 1 from public.desktop_sessions ds join auth.users u on u.id=ds.user_id
        where ds.device_identity_id=d.id and lower(u.email) like '%'||v_query||'%'))
  ) x),'[]'::jsonb);
end;
$$;

create or replace function public.paxinbot_owner_reset_security_risk(p_device_identity_id uuid)
returns jsonb language plpgsql security definer set search_path=public,auth,pg_temp as $$
begin
  perform public.paxinbot_require_owner();
  update public.security_risk_state set score=0,level='normal',restricted_until=null,
    reviewed_at=now(),reviewed_by=auth.uid(),updated_at=now() where device_identity_id=p_device_identity_id;
  if not found then raise exception 'security_risk_not_found'; end if;
  insert into public.audit_events(user_id,event_type,metadata) values(auth.uid(),'owner.security_risk_reset',
    jsonb_build_object('deviceIdentityId',p_device_identity_id));
  return jsonb_build_object('ok',true);
end;
$$;

-- A restrição temporária é verificada antes da função de sessão já existente.
create or replace function public.paxinbot_desktop_session_v3(p_token_hash text)
returns jsonb language plpgsql security definer set search_path=public,auth,pg_temp as $$
declare v_session public.desktop_sessions%rowtype; v_identity public.device_identities%rowtype;
  v_risk public.security_risk_state%rowtype; v_result jsonb;
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
  select * into v_risk from public.security_risk_state where device_identity_id=v_identity.id;
  if found and v_risk.restricted_until>now() then
    update public.desktop_sessions set revoked_at=coalesce(revoked_at,now()) where id=v_session.id;
    return jsonb_build_object('active',false,'reason','risk_reauthentication_required');
  end if;
  v_result:=public.paxinbot_desktop_session_v2(p_token_hash);
  update public.device_identities set last_seen_at=now() where id=v_identity.id;
  return v_result;
end;
$$;

revoke all on function public.paxinbot_record_security_event(text,uuid,text,timestamptz,text,integer,jsonb) from public,anon,authenticated;
revoke all on function public.paxinbot_record_device_security_event(text,text,uuid,text,text) from public,anon,authenticated;
revoke all on function public.paxinbot_owner_list_security_risk(text) from public;
revoke all on function public.paxinbot_owner_reset_security_risk(uuid) from public;
revoke all on function public.paxinbot_desktop_session_v3(text) from public,anon,authenticated;
grant execute on function public.paxinbot_record_security_event(text,uuid,text,timestamptz,text,integer,jsonb) to service_role;
grant execute on function public.paxinbot_record_device_security_event(text,text,uuid,text,text) to service_role;
grant execute on function public.paxinbot_owner_list_security_risk(text) to authenticated;
grant execute on function public.paxinbot_owner_reset_security_risk(uuid) to authenticated;
grant execute on function public.paxinbot_desktop_session_v3(text) to service_role;
