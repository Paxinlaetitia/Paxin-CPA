-- Cash Hunters licensing v1. This schema is deliberately independent from
-- Paxinbot entitlements and desktop sessions.

begin;

create table if not exists public.cpa_licenses (
  id uuid primary key default extensions.gen_random_uuid(),
  product_code text not null default 'cash-hunters' check (product_code='cash-hunters'),
  key_id text not null unique check (key_id ~ '^[A-Za-z0-9_-]{16}$'),
  key_prefix text not null check (key_prefix ~ '^[A-Za-z0-9_-]{8}$'),
  key_hmac text not null check (key_hmac ~ '^[a-f0-9]{64}$'),
  pepper_version text not null check (pepper_version ~ '^[A-Za-z0-9._-]{1,32}$'),
  customer_id uuid references auth.users(id) on delete set null,
  activation_policy text not null check (activation_policy in ('first','immediate')),
  duration_unit text not null check (duration_unit in ('hours','days','weeks','months','lifetime','custom')),
  duration_value integer check (duration_value is null or duration_value between 1 and 10000),
  custom_expires_at timestamptz,
  status text not null check (status in ('pending','inactive','active','suspended','revoked','banned')),
  starts_at timestamptz,
  expires_at timestamptz,
  activated_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint cpa_license_duration check (
    (duration_unit='lifetime' and duration_value is null and custom_expires_at is null) or
    (duration_unit='custom' and duration_value is null and custom_expires_at is not null) or
    (duration_unit in ('hours','days','weeks','months') and duration_value is not null and custom_expires_at is null)
  ),
  unique (pepper_version,key_hmac)
);

create table if not exists public.cpa_devices (
  id uuid primary key default extensions.gen_random_uuid(),
  license_id uuid not null references public.cpa_licenses(id) on delete cascade,
  hwid_hash text not null check (hwid_hash ~ '^[a-f0-9]{64}$'),
  public_key text not null check (public_key ~ '^[A-Za-z0-9_-]{40,255}$'),
  public_key_hash text not null check (public_key_hash ~ '^[a-f0-9]{64}$'),
  status text not null default 'active' check (status in ('active','replaced')),
  created_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  replaced_at timestamptz
);
create unique index if not exists cpa_devices_one_active_per_license
  on public.cpa_devices(license_id) where status='active';
create index if not exists cpa_devices_hwid_idx on public.cpa_devices(hwid_hash);

create table if not exists public.cpa_device_bans (
  hwid_hash text primary key check (hwid_hash ~ '^[a-f0-9]{64}$'),
  banned_at timestamptz not null default now(),
  banned_by uuid references auth.users(id) on delete set null
);

create table if not exists public.cpa_sessions (
  id uuid primary key default extensions.gen_random_uuid(),
  license_id uuid not null references public.cpa_licenses(id) on delete cascade,
  device_id uuid not null references public.cpa_devices(id) on delete cascade,
  token_hash text not null unique check (token_hash ~ '^[a-f0-9]{64}$'),
  release_id text not null check (release_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$'),
  expires_at timestamptz not null,
  created_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  revoked_at timestamptz
);
create index if not exists cpa_sessions_license_idx on public.cpa_sessions(license_id,expires_at desc);

create table if not exists public.cpa_challenges (
  id uuid primary key,
  product_code text not null default 'cash-hunters' check (product_code='cash-hunters'),
  action text not null check (action in ('activate','refresh','authorize','logout')),
  payload_hash text not null check (payload_hash ~ '^[a-f0-9]{64}$'),
  nonce text not null check (nonce ~ '^[A-Za-z0-9_-]{43}$'),
  request_nonce_hash text unique check (request_nonce_hash is null or request_nonce_hash ~ '^[a-f0-9]{64}$'),
  expires_at timestamptz not null default (now()+interval '60 seconds'),
  consumed_at timestamptz,
  created_at timestamptz not null default now()
);
create index if not exists cpa_challenges_expiry_idx on public.cpa_challenges(expires_at);

create table if not exists public.cpa_audit (
  id uuid primary key default extensions.gen_random_uuid(),
  actor_user_id uuid references auth.users(id) on delete set null,
  license_id uuid references public.cpa_licenses(id) on delete set null,
  device_id uuid references public.cpa_devices(id) on delete set null,
  category text not null check (category ~ '^[a-z0-9_.-]{3,64}$'),
  created_at timestamptz not null default now()
);
create index if not exists cpa_audit_created_idx on public.cpa_audit(created_at desc);

alter table public.cpa_licenses enable row level security;
alter table public.cpa_devices enable row level security;
alter table public.cpa_device_bans enable row level security;
alter table public.cpa_sessions enable row level security;
alter table public.cpa_challenges enable row level security;
alter table public.cpa_audit enable row level security;
revoke all on table public.cpa_licenses,public.cpa_devices,public.cpa_device_bans,
  public.cpa_sessions,public.cpa_challenges,public.cpa_audit from public,anon,authenticated;

create or replace function public.cpa_require_service_role()
returns void language plpgsql stable security definer set search_path=public,auth,pg_temp as $$
begin
  if auth.role() is distinct from 'service_role' then raise exception 'service_role_required'; end if;
end;
$$;

create or replace function public.cpa_license_expiry(p_unit text,p_value integer,p_custom timestamptz,p_base timestamptz)
returns timestamptz language plpgsql stable set search_path=public,pg_temp set timezone='UTC' as $$
begin
  case p_unit
    when 'lifetime' then return null;
    when 'custom' then return p_custom;
    when 'hours' then return p_base+make_interval(hours=>p_value);
    when 'days' then return p_base+make_interval(days=>p_value);
    when 'weeks' then return p_base+make_interval(weeks=>p_value);
    when 'months' then return p_base+make_interval(months=>p_value);
    else raise exception 'invalid_request';
  end case;
end;
$$;

create or replace function public.cpa_license_create_challenge(
  p_challenge_id uuid,p_action text,p_payload_hash text,p_nonce text
) returns jsonb language plpgsql security definer set search_path=public,auth,pg_temp as $$
begin
  perform public.cpa_require_service_role();
  if coalesce(p_action,'') not in ('activate','refresh','authorize','logout') or coalesce(p_payload_hash,'') !~ '^[a-f0-9]{64}$'
    or coalesce(p_nonce,'') !~ '^[A-Za-z0-9_-]{43}$' then raise exception 'invalid_request'; end if;
  delete from public.cpa_challenges where expires_at<now()-interval '24 hours';
  delete from public.cpa_sessions where expires_at<now()-interval '30 days';
  delete from public.cpa_audit where id in (
    select id from public.cpa_audit where created_at<now()-interval '365 days'
    order by created_at limit 1000
  );
  insert into public.cpa_challenges(id,action,payload_hash,nonce) values(p_challenge_id,p_action,p_payload_hash,p_nonce);
  return jsonb_build_object('challengeId',p_challenge_id,'expiresIn',60);
end;
$$;

create or replace function public.cpa_license_consume_challenge(p_challenge_id uuid)
returns jsonb language plpgsql security definer set search_path=public,auth,pg_temp as $$
declare v public.cpa_challenges%rowtype;
begin
  perform public.cpa_require_service_role();
  select * into v from public.cpa_challenges where id=p_challenge_id for update;
  if not found then raise exception 'invalid_request'; end if;
  if v.consumed_at is not null then return jsonb_build_object('status','replay'); end if;
  update public.cpa_challenges set consumed_at=now() where id=v.id;
  if v.expires_at<=now() then return jsonb_build_object('status','expired'); end if;
  return jsonb_build_object('status','ready','action',v.action,'payloadHash',v.payload_hash,'nonce',v.nonce);
end;
$$;

create or replace function public.cpa_license_register_proof(p_challenge_id uuid,p_request_nonce_hash text)
returns boolean language plpgsql security definer set search_path=public,auth,pg_temp as $$
begin
  perform public.cpa_require_service_role();
  if coalesce(p_request_nonce_hash,'') !~ '^[a-f0-9]{64}$' then raise exception 'invalid_proof'; end if;
  update public.cpa_challenges set request_nonce_hash=p_request_nonce_hash
    where id=p_challenge_id and consumed_at is not null and request_nonce_hash is null;
  if not found then raise exception 'replay'; end if;
  return true;
exception when unique_violation then raise exception 'replay';
end;
$$;

create or replace function public.cpa_license_record_denial(p_category text,p_hwid text default null,p_session_token_hash text default null)
returns boolean language plpgsql security definer set search_path=public,auth,pg_temp as $$
declare v_license uuid; v_device uuid;
begin
  perform public.cpa_require_service_role();
  if coalesce(p_category,'') not in ('license.denied_invalid_proof','license.denied_invalid_key','license.denied_expired',
    'license.denied_suspended','license.denied_revoked','license.denied_banned','license.denied_hwid_mismatch',
    'license.denied_device_banned','license.denied_session_expired','license.denied_release_unknown') then return false; end if;
  if p_hwid is not null and p_hwid !~ '^[a-f0-9]{64}$' then return false; end if;
  if p_session_token_hash is not null and p_session_token_hash !~ '^[a-f0-9]{64}$' then return false; end if;
  select s.license_id,s.device_id into v_license,v_device from public.cpa_sessions s
    where s.token_hash=p_session_token_hash limit 1;
  if v_device is null and p_hwid is not null then
    select d.license_id,d.id into v_license,v_device from public.cpa_devices d
      where d.hwid_hash=p_hwid order by d.last_seen_at desc limit 1;
  end if;
  insert into public.cpa_audit(license_id,device_id,category) values(v_license,v_device,p_category);
  return true;
end;
$$;

create or replace function public.cpa_assert_license(p_license_id uuid)
returns public.cpa_licenses language plpgsql volatile security definer set search_path=public,auth,pg_temp as $$
declare v public.cpa_licenses%rowtype;
begin
  select * into v from public.cpa_licenses where id=p_license_id for update;
  if not found then raise exception 'invalid_key'; end if;
  if v.status='suspended' then raise exception 'suspended'; end if;
  if v.status='revoked' then raise exception 'revoked'; end if;
  if v.status='banned' then raise exception 'banned'; end if;
  if v.status<>'active' then raise exception 'invalid_key'; end if;
  if v.expires_at is not null and v.expires_at<=now() then raise exception 'expired'; end if;
  return v;
end;
$$;

create or replace function public.cpa_session_result(p_license public.cpa_licenses,p_session_expires timestamptz)
returns jsonb language sql stable set search_path=public,pg_temp as $$
  select jsonb_build_object(
    'licenseId',p_license.id,'serverTime',now(),
    'expiresIn',greatest(0,least(120,floor(extract(epoch from (p_session_expires-now())))::integer)),
    'licenseExpiresAt',p_license.expires_at
  );
$$;

create or replace function public.cpa_license_activate(
  p_candidates jsonb,p_hwid text,p_public_key text,p_public_key_hash text,
  p_release_id text,p_session_token_hash text
) returns jsonb language plpgsql security definer set search_path=public,auth,pg_temp as $$
declare l public.cpa_licenses%rowtype; d public.cpa_devices%rowtype; session_exp timestamptz;
begin
  perform public.cpa_require_service_role();
  if jsonb_typeof(p_candidates) is distinct from 'array' or jsonb_array_length(p_candidates) not between 1 and 8
    or exists(select 1 from jsonb_array_elements(p_candidates) c where coalesce(c->>'version','') !~ '^[A-Za-z0-9._-]{1,32}$' or coalesce(c->>'hash','') !~ '^[a-f0-9]{64}$')
    or coalesce(p_hwid,'') !~ '^[a-f0-9]{64}$' or coalesce(p_public_key_hash,'') !~ '^[a-f0-9]{64}$'
    or coalesce(p_public_key,'') !~ '^[A-Za-z0-9_-]{40,255}$' or coalesce(p_release_id,'') !~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$'
    or coalesce(p_session_token_hash,'') !~ '^[a-f0-9]{64}$' then raise exception 'invalid_request'; end if;
  perform pg_advisory_xact_lock(hashtextextended('cash-hunters:'||p_hwid,0));
  select x.* into l from public.cpa_licenses x where x.product_code='cash-hunters' and exists(
    select 1 from jsonb_array_elements(p_candidates) c
    where c->>'version'=x.pepper_version and c->>'hash'=x.key_hmac
  ) for update;
  if not found then raise exception 'invalid_key'; end if;
  if exists(select 1 from public.cpa_device_bans where hwid_hash=p_hwid) then raise exception 'device_banned'; end if;
  if l.status='pending' and l.activation_policy='first' and l.activated_at is null then
    update public.cpa_licenses set status='active',starts_at=now(),activated_at=coalesce(activated_at,now()),
      expires_at=public.cpa_license_expiry(duration_unit,duration_value,custom_expires_at,now()),updated_at=now()
      where id=l.id returning * into l;
  end if;
  l:=public.cpa_assert_license(l.id);
  select * into d from public.cpa_devices where license_id=l.id and status='active' for update;
  if found and (d.hwid_hash<>p_hwid or d.public_key_hash<>p_public_key_hash or d.public_key<>p_public_key) then raise exception 'hwid_mismatch'; end if;
  if not found then
    insert into public.cpa_devices(license_id,hwid_hash,public_key,public_key_hash)
      values(l.id,p_hwid,p_public_key,p_public_key_hash) returning * into d;
    insert into public.cpa_audit(license_id,device_id,category) values(l.id,d.id,'license.device_bound');
  end if;
  session_exp:=least(now()+interval '120 seconds',coalesce(l.expires_at,'infinity'::timestamptz));
  insert into public.cpa_sessions(license_id,device_id,token_hash,release_id,expires_at)
    values(l.id,d.id,p_session_token_hash,p_release_id,session_exp);
  update public.cpa_devices set last_seen_at=now() where id=d.id;
  insert into public.cpa_audit(license_id,device_id,category) values(l.id,d.id,'license.activated');
  return public.cpa_session_result(l,session_exp);
end;
$$;

create or replace function public.cpa_license_refresh(
  p_session_token_hash text,p_new_session_token_hash text,p_hwid text,p_public_key_hash text,p_release_id text
) returns jsonb language plpgsql security definer set search_path=public,auth,pg_temp as $$
declare s public.cpa_sessions%rowtype; d public.cpa_devices%rowtype; l public.cpa_licenses%rowtype; session_exp timestamptz;
begin
  perform public.cpa_require_service_role();
  if coalesce(p_session_token_hash,'') !~ '^[a-f0-9]{64}$' or coalesce(p_new_session_token_hash,'') !~ '^[a-f0-9]{64}$'
    or coalesce(p_hwid,'') !~ '^[a-f0-9]{64}$' or coalesce(p_public_key_hash,'') !~ '^[a-f0-9]{64}$'
    or coalesce(p_release_id,'') !~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$' then raise exception 'invalid_request'; end if;
  select * into s from public.cpa_sessions where token_hash=p_session_token_hash;
  if not found or s.revoked_at is not null or s.expires_at<=now() then raise exception 'session_expired'; end if;
  perform pg_advisory_xact_lock(hashtextextended('cash-hunters:'||p_hwid,0));
  l:=public.cpa_assert_license(s.license_id);
  select * into s from public.cpa_sessions where id=s.id for update;
  if s.token_hash is distinct from p_session_token_hash or s.revoked_at is not null or s.expires_at<=now() then raise exception 'session_expired'; end if;
  select * into d from public.cpa_devices where id=s.device_id for update;
  if d.status is distinct from 'active' or d.hwid_hash is distinct from p_hwid or d.public_key_hash is distinct from p_public_key_hash then raise exception 'hwid_mismatch'; end if;
  if exists(select 1 from public.cpa_device_bans where hwid_hash=p_hwid) then raise exception 'device_banned'; end if;
  if s.release_id is distinct from p_release_id then raise exception 'release_unknown'; end if;
  session_exp:=least(now()+interval '120 seconds',coalesce(l.expires_at,'infinity'::timestamptz));
  update public.cpa_sessions set token_hash=p_new_session_token_hash,expires_at=session_exp,last_seen_at=now() where id=s.id;
  update public.cpa_devices set last_seen_at=now() where id=d.id;
  return public.cpa_session_result(l,session_exp);
end;
$$;

create or replace function public.cpa_license_authorize(
  p_session_token_hash text,p_hwid text,p_public_key_hash text,p_release_id text,p_scope text
) returns jsonb language plpgsql security definer set search_path=public,auth,pg_temp as $$
declare s public.cpa_sessions%rowtype; d public.cpa_devices%rowtype; l public.cpa_licenses%rowtype;
begin
  perform public.cpa_require_service_role();
  if coalesce(p_scope,'') not in ('start','manager','operation','browser') or coalesce(p_session_token_hash,'') !~ '^[a-f0-9]{64}$'
    or coalesce(p_hwid,'') !~ '^[a-f0-9]{64}$' or coalesce(p_public_key_hash,'') !~ '^[a-f0-9]{64}$'
    or coalesce(p_release_id,'') !~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$' then raise exception 'invalid_request'; end if;
  select * into s from public.cpa_sessions where token_hash=p_session_token_hash;
  if not found or s.revoked_at is not null or s.expires_at<=now() then raise exception 'session_expired'; end if;
  perform pg_advisory_xact_lock(hashtextextended('cash-hunters:'||p_hwid,0));
  l:=public.cpa_assert_license(s.license_id);
  select * into s from public.cpa_sessions where id=s.id for update;
  if s.token_hash is distinct from p_session_token_hash or s.revoked_at is not null or s.expires_at<=now() then raise exception 'session_expired'; end if;
  select * into d from public.cpa_devices where id=s.device_id;
  if d.status is distinct from 'active' or d.hwid_hash is distinct from p_hwid or d.public_key_hash is distinct from p_public_key_hash then raise exception 'hwid_mismatch'; end if;
  if exists(select 1 from public.cpa_device_bans where hwid_hash=p_hwid) then raise exception 'device_banned'; end if;
  if s.release_id is distinct from p_release_id then raise exception 'release_unknown'; end if;
  update public.cpa_sessions set last_seen_at=now() where id=s.id;
  insert into public.cpa_audit(license_id,device_id,category) values(l.id,d.id,'license.authorized_'||p_scope);
  return public.cpa_session_result(l,s.expires_at);
end;
$$;

create or replace function public.cpa_license_logout(p_session_token_hash text,p_hwid text,p_public_key_hash text)
returns jsonb language plpgsql security definer set search_path=public,auth,pg_temp as $$
declare s public.cpa_sessions%rowtype; d public.cpa_devices%rowtype; l public.cpa_licenses%rowtype;
begin
  perform public.cpa_require_service_role();
  if coalesce(p_session_token_hash,'') !~ '^[a-f0-9]{64}$' or coalesce(p_hwid,'') !~ '^[a-f0-9]{64}$'
    or coalesce(p_public_key_hash,'') !~ '^[a-f0-9]{64}$' then raise exception 'invalid_request'; end if;
  select * into s from public.cpa_sessions where token_hash=p_session_token_hash;
  if not found or s.revoked_at is not null then raise exception 'session_expired'; end if;
  perform pg_advisory_xact_lock(hashtextextended('cash-hunters:'||p_hwid,0));
  select * into l from public.cpa_licenses where id=s.license_id for update;
  select * into s from public.cpa_sessions where id=s.id for update;
  if s.token_hash is distinct from p_session_token_hash or s.revoked_at is not null or s.expires_at<=now() then raise exception 'session_expired'; end if;
  select * into d from public.cpa_devices where id=s.device_id;
  if d.hwid_hash is distinct from p_hwid or d.public_key_hash is distinct from p_public_key_hash then raise exception 'hwid_mismatch'; end if;
  update public.cpa_sessions set revoked_at=now(),expires_at=least(expires_at,now()),last_seen_at=now() where id=s.id;
  insert into public.cpa_audit(license_id,device_id,category) values(s.license_id,d.id,'license.logout');
  return jsonb_build_object('licenseId',s.license_id,'serverTime',now(),'expiresIn',0,'licenseExpiresAt',null);
end;
$$;

create or replace function public.cpa_owner_list_licenses(p_query text default '',p_status text default null,p_limit integer default 200)
returns jsonb language plpgsql stable security definer set search_path=public,auth,pg_temp as $$
begin
  if public.paxinbot_is_owner() is not true then raise exception 'owner_required'; end if;
  if char_length(coalesce(p_query,''))>120 or coalesce(p_status,'') not in ('','pending','inactive','active','suspended','revoked','banned','expired') then raise exception 'invalid_request'; end if;
  return coalesce((select jsonb_agg(row_to_json(x)) from (
    select l.id,l.key_id as "keyId",l.key_prefix as "keyPrefix",l.customer_id as "customerId",u.email,
      case when l.status='active' and l.expires_at is not null and l.expires_at<=now() then 'expired' else l.status end status,
      l.activation_policy as "activationPolicy",l.duration_unit as "durationUnit",l.duration_value as "durationValue",
      l.starts_at as "startsAt",l.expires_at as "expiresAt",l.activated_at as "activatedAt",l.created_at as "createdAt",
      d.id as "deviceId",d.hwid_hash as "hwid",d.public_key_hash as "publicKeyHash",d.last_seen_at as "deviceLastSeenAt",
      (select count(*) from public.cpa_sessions s where s.license_id=l.id and s.revoked_at is null and s.expires_at>now()) as "activeSessions",
      (select max(s.last_seen_at) from public.cpa_sessions s where s.license_id=l.id) as "sessionLastSeenAt"
    from public.cpa_licenses l left join auth.users u on u.id=l.customer_id
    left join public.cpa_devices d on d.license_id=l.id and d.status='active'
    where (coalesce(p_query,'')='' or l.key_id ilike '%'||p_query||'%' or l.key_prefix ilike '%'||p_query||'%' or coalesce(u.email,'') ilike '%'||p_query||'%')
      and (coalesce(p_status,'')='' or (p_status='expired' and l.status='active' and l.expires_at<=now()) or (p_status<>'expired' and l.status=p_status and not (p_status='active' and l.expires_at is not null and l.expires_at<=now())))
    order by l.created_at desc limit greatest(1,least(coalesce(p_limit,200),200))
  ) x),'[]'::jsonb);
end;
$$;

create or replace function public.cpa_owner_list_license_audit(p_limit integer default 200)
returns jsonb language plpgsql stable security definer set search_path=public,auth,pg_temp as $$
begin
  if public.paxinbot_is_owner() is not true then raise exception 'owner_required'; end if;
  return coalesce((select jsonb_agg(row_to_json(x)) from (
    select id,actor_user_id as "actorUserId",license_id as "licenseId",device_id as "deviceId",category,created_at as "createdAt"
    from public.cpa_audit order by created_at desc limit greatest(1,least(coalesce(p_limit,200),200))
  ) x),'[]'::jsonb);
end;
$$;

create or replace function public.cpa_owner_create_license(
  p_key_id text,p_key_prefix text,p_key_hmac text,p_pepper_version text,p_duration_unit text,
  p_duration_value integer,p_custom_expires_at timestamptz,p_activation_policy text,p_customer_id uuid default null
) returns jsonb language plpgsql security definer set search_path=public,auth,pg_temp as $$
declare l public.cpa_licenses%rowtype; base timestamptz:=now();
begin
  if public.paxinbot_is_owner() is not true then raise exception 'owner_required'; end if;
  if coalesce(p_activation_policy,'') not in ('first','immediate') or coalesce(p_duration_unit,'') not in ('hours','days','weeks','months','lifetime','custom')
    or coalesce(p_key_hmac,'') !~ '^[a-f0-9]{64}$' then raise exception 'invalid_request'; end if;
  if p_duration_unit='custom' and (p_custom_expires_at is null or p_custom_expires_at<=base) then raise exception 'invalid_request'; end if;
  insert into public.cpa_licenses(key_id,key_prefix,key_hmac,pepper_version,customer_id,activation_policy,duration_unit,duration_value,custom_expires_at,status,starts_at,expires_at,activated_at)
    values(p_key_id,p_key_prefix,p_key_hmac,p_pepper_version,p_customer_id,p_activation_policy,p_duration_unit,p_duration_value,p_custom_expires_at,
      case when p_activation_policy='immediate' then 'active' else 'pending' end,
      case when p_activation_policy='immediate' then base end,
      case when p_activation_policy='immediate' then public.cpa_license_expiry(p_duration_unit,p_duration_value,p_custom_expires_at,base) end,
      case when p_activation_policy='immediate' then base end)
    returning * into l;
  insert into public.cpa_audit(actor_user_id,license_id,category) values(auth.uid(),l.id,'owner.license_created');
  return jsonb_build_object('id',l.id,'keyId',l.key_id,'keyPrefix',l.key_prefix,'status',l.status,'activationPolicy',l.activation_policy,'durationUnit',l.duration_unit,'durationValue',l.duration_value,'expiresAt',l.expires_at,'createdAt',l.created_at);
end;
$$;

create or replace function public.cpa_owner_update_license(
  p_license_id uuid,p_operation text,p_duration_unit text default null,p_duration_value integer default null,
  p_expires_at timestamptz default null,p_hwid text default null,p_public_key text default null,p_public_key_hash text default null
) returns jsonb language plpgsql security definer set search_path=public,auth,pg_temp as $$
declare l public.cpa_licenses%rowtype; d public.cpa_devices%rowtype; base timestamptz;
begin
  if public.paxinbot_is_owner() is not true then raise exception 'owner_required'; end if;
  select * into l from public.cpa_licenses where id=p_license_id for update;
  if not found or coalesce(p_operation,'') not in ('activate','deactivate','suspend','revoke','ban','unban','reset_device','replace_device','extend','set_expiration','terminate_sessions') then raise exception 'invalid_request'; end if;
  if l.status='revoked' and p_operation<>'terminate_sessions' then raise exception 'revoked'; end if;
  if p_operation='activate' then
    base:=coalesce(l.starts_at,now());
    update public.cpa_licenses set status='active',starts_at=base,activated_at=coalesce(activated_at,now()),
      expires_at=coalesce(expires_at,public.cpa_license_expiry(duration_unit,duration_value,custom_expires_at,base)),updated_at=now() where id=l.id;
  elsif p_operation='deactivate' then update public.cpa_licenses set status='inactive',updated_at=now() where id=l.id;
  elsif p_operation='suspend' then update public.cpa_licenses set status='suspended',updated_at=now() where id=l.id;
  elsif p_operation='revoke' then update public.cpa_licenses set status='revoked',updated_at=now() where id=l.id;
  elsif p_operation='ban' then update public.cpa_licenses set status='banned',updated_at=now() where id=l.id;
  elsif p_operation='unban' then update public.cpa_licenses set status='inactive',updated_at=now() where id=l.id;
  elsif p_operation='reset_device' then
    update public.cpa_devices set status='replaced',replaced_at=now() where license_id=l.id and status='active';
  elsif p_operation='replace_device' then
    if coalesce(p_hwid,'') !~ '^[a-f0-9]{64}$' or coalesce(p_public_key,'') !~ '^[A-Za-z0-9_-]{40,255}$' or coalesce(p_public_key_hash,'') !~ '^[a-f0-9]{64}$' then raise exception 'invalid_request'; end if;
    if exists(select 1 from public.cpa_device_bans where hwid_hash=p_hwid) then raise exception 'device_banned'; end if;
    update public.cpa_devices set status='replaced',replaced_at=now() where license_id=l.id and status='active';
    insert into public.cpa_devices(license_id,hwid_hash,public_key,public_key_hash) values(l.id,p_hwid,p_public_key,p_public_key_hash) returning * into d;
  elsif p_operation='extend' then
    if coalesce(p_duration_unit,'') not in ('hours','days','weeks','months','lifetime','custom') then raise exception 'invalid_request'; end if;
    base:=greatest(now(),coalesce(l.expires_at,now()));
    update public.cpa_licenses set duration_unit=p_duration_unit,duration_value=p_duration_value,custom_expires_at=case when p_duration_unit='custom' then p_expires_at end,
      expires_at=public.cpa_license_expiry(p_duration_unit,p_duration_value,p_expires_at,base),updated_at=now() where id=l.id;
  elsif p_operation='set_expiration' then
    if p_expires_at is not null and p_expires_at<=now() then raise exception 'invalid_request'; end if;
    update public.cpa_licenses set duration_unit=case when p_expires_at is null then 'lifetime' else 'custom' end,duration_value=null,custom_expires_at=p_expires_at,expires_at=p_expires_at,updated_at=now() where id=l.id;
  end if;
  if p_operation in ('deactivate','suspend','revoke','ban','reset_device','replace_device','terminate_sessions') then
    update public.cpa_sessions set revoked_at=coalesce(revoked_at,now()),expires_at=least(expires_at,now()) where license_id=l.id and revoked_at is null;
  end if;
  insert into public.cpa_audit(actor_user_id,license_id,device_id,category) values(auth.uid(),l.id,d.id,'owner.'||p_operation);
  select * into l from public.cpa_licenses where id=l.id;
  return jsonb_build_object('id',l.id,'keyId',l.key_id,'keyPrefix',l.key_prefix,'status',l.status,'startsAt',l.starts_at,'expiresAt',l.expires_at,'updatedAt',l.updated_at);
end;
$$;

create or replace function public.cpa_owner_set_device_ban(p_hwid text,p_banned boolean)
returns jsonb language plpgsql security definer set search_path=public,auth,pg_temp as $$
begin
  if public.paxinbot_is_owner() is not true then raise exception 'owner_required'; end if;
  if coalesce(p_hwid,'') !~ '^[a-f0-9]{64}$' or p_banned is null then raise exception 'invalid_request'; end if;
  perform pg_advisory_xact_lock(hashtextextended('cash-hunters:'||p_hwid,0));
  if p_banned then
    insert into public.cpa_device_bans(hwid_hash,banned_by) values(p_hwid,auth.uid()) on conflict(hwid_hash) do update set banned_at=now(),banned_by=auth.uid();
    update public.cpa_sessions s set revoked_at=coalesce(s.revoked_at,now()),expires_at=least(s.expires_at,now())
      from public.cpa_devices d where s.device_id=d.id and d.hwid_hash=p_hwid and s.revoked_at is null;
  else delete from public.cpa_device_bans where hwid_hash=p_hwid;
  end if;
  insert into public.cpa_audit(actor_user_id,device_id,category)
    select auth.uid(),(select id from public.cpa_devices where hwid_hash=p_hwid order by last_seen_at desc limit 1),case when p_banned then 'owner.device_banned' else 'owner.device_unbanned' end;
  return jsonb_build_object('hwid',p_hwid,'banned',p_banned);
end;
$$;

revoke all on function public.cpa_require_service_role() from public,anon,authenticated;
revoke all on function public.cpa_license_expiry(text,integer,timestamptz,timestamptz) from public,anon,authenticated;
revoke all on function public.cpa_assert_license(uuid) from public,anon,authenticated;
revoke all on function public.cpa_session_result(public.cpa_licenses,timestamptz) from public,anon,authenticated;
revoke all on function public.cpa_license_create_challenge(uuid,text,text,text) from public,anon,authenticated;
revoke all on function public.cpa_license_consume_challenge(uuid) from public,anon,authenticated;
revoke all on function public.cpa_license_register_proof(uuid,text) from public,anon,authenticated;
revoke all on function public.cpa_license_record_denial(text,text,text) from public,anon,authenticated;
revoke all on function public.cpa_license_activate(jsonb,text,text,text,text,text) from public,anon,authenticated;
revoke all on function public.cpa_license_refresh(text,text,text,text,text) from public,anon,authenticated;
revoke all on function public.cpa_license_authorize(text,text,text,text,text) from public,anon,authenticated;
revoke all on function public.cpa_license_logout(text,text,text) from public,anon,authenticated;
grant execute on function public.cpa_license_create_challenge(uuid,text,text,text) to service_role;
grant execute on function public.cpa_license_consume_challenge(uuid) to service_role;
grant execute on function public.cpa_license_register_proof(uuid,text) to service_role;
grant execute on function public.cpa_license_record_denial(text,text,text) to service_role;
grant execute on function public.cpa_license_activate(jsonb,text,text,text,text,text) to service_role;
grant execute on function public.cpa_license_refresh(text,text,text,text,text) to service_role;
grant execute on function public.cpa_license_authorize(text,text,text,text,text) to service_role;
grant execute on function public.cpa_license_logout(text,text,text) to service_role;

revoke all on function public.cpa_owner_list_licenses(text,text,integer) from public,anon;
revoke all on function public.cpa_owner_list_license_audit(integer) from public,anon;
revoke all on function public.cpa_owner_create_license(text,text,text,text,text,integer,timestamptz,text,uuid) from public,anon;
revoke all on function public.cpa_owner_update_license(uuid,text,text,integer,timestamptz,text,text,text) from public,anon;
revoke all on function public.cpa_owner_set_device_ban(text,boolean) from public,anon;
grant execute on function public.cpa_owner_list_licenses(text,text,integer) to authenticated;
grant execute on function public.cpa_owner_list_license_audit(integer) to authenticated;
grant execute on function public.cpa_owner_create_license(text,text,text,text,text,integer,timestamptz,text,uuid) to authenticated;
grant execute on function public.cpa_owner_update_license(uuid,text,text,integer,timestamptz,text,text,text) to authenticated;
grant execute on function public.cpa_owner_set_device_ban(text,boolean) to authenticated;

commit;
