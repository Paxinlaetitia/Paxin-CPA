-- Paxinbot: reserva atomica de autorizacoes curtas para releases protegidas.
-- Execute depois de 20260827_security_risk.sql.

create table if not exists public.protected_release_authorizations (
  id uuid primary key default extensions.gen_random_uuid(),
  desktop_session_id uuid not null references public.desktop_sessions(id) on delete cascade,
  device_identity_id uuid not null references public.device_identities(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  request_nonce_hash text not null unique check (request_nonce_hash ~ '^[a-f0-9]{64}$'),
  app_version text not null check (app_version ~ '^\d{1,4}(\.\d{1,4}){1,3}(-[0-9A-Za-z.-]{1,24})?$'),
  release_sequence integer not null check (release_sequence between 1 and 2147483647),
  integrity_digest text not null check (integrity_digest ~ '^[a-f0-9]{64}$'),
  module_index_digest text not null check (module_index_digest ~ '^[a-f0-9]{64}$'),
  issued_at timestamptz not null default now(),
  expires_at timestamptz not null default (now() + interval '2 minutes'),
  constraint protected_release_authorization_expiry check (expires_at > issued_at and expires_at <= issued_at + interval '2 minutes')
);

create index if not exists protected_release_authorizations_session_idx
  on public.protected_release_authorizations(desktop_session_id,issued_at desc);
create index if not exists protected_release_authorizations_expiry_idx
  on public.protected_release_authorizations(expires_at);
alter table public.protected_release_authorizations enable row level security;
revoke all on table public.protected_release_authorizations from public,anon,authenticated;

create or replace function public.paxinbot_authorize_protected_release(
  p_token_hash text,
  p_version text,
  p_sequence integer,
  p_integrity_digest text,
  p_index_digest text,
  p_request_nonce_hash text
)
returns jsonb language plpgsql security definer set search_path=public,auth,pg_temp as $$
declare
  v_session public.desktop_sessions%rowtype;
  v_identity public.device_identities%rowtype;
  v_user auth.users%rowtype;
  v_risk public.security_risk_state%rowtype;
  v_access record;
begin
  if auth.role()<>'service_role' then raise exception 'service_role_required'; end if;
  if p_token_hash !~ '^[a-f0-9]{64}$' or p_integrity_digest !~ '^[a-f0-9]{64}$'
    or p_index_digest !~ '^[a-f0-9]{64}$' or p_request_nonce_hash !~ '^[a-f0-9]{64}$'
    or p_version !~ '^\d{1,4}(\.\d{1,4}){1,3}(-[0-9A-Za-z.-]{1,24})?$'
    or p_sequence not between 1 and 2147483647 then raise exception 'protected_release_request_invalid'; end if;

  select * into v_session from public.desktop_sessions where token_hash=p_token_hash for update;
  if not found or v_session.revoked_at is not null or v_session.expires_at<=now()
    or v_session.device_identity_id is null then raise exception 'desktop_session_invalid'; end if;
  if v_session.app_version<>p_version then raise exception 'protected_release_version_mismatch'; end if;

  select * into v_user from auth.users where id=v_session.user_id;
  if not found or v_user.email_confirmed_at is null then raise exception 'account_unverified'; end if;
  if not exists(select 1 from public.profiles where id=v_session.user_id and disabled_at is null) then
    raise exception 'account_disabled';
  end if;

  select * into v_identity from public.device_identities where id=v_session.device_identity_id for update;
  if not found or v_identity.banned_at is not null
    or exists(select 1 from public.device_identities where fingerprint_hash=v_identity.fingerprint_hash and banned_at is not null) then
    raise exception 'device_banned';
  end if;

  select * into v_risk from public.security_risk_state where device_identity_id=v_identity.id;
  if found and v_risk.restricted_until>now() then raise exception 'risk_reauthentication_required'; end if;

  select * into v_access from public.paxinbot_active_entitlement(v_session.user_id);
  if not found then raise exception 'no_active_access'; end if;
  if exists(select 1 from public.protected_release_authorizations where request_nonce_hash=p_request_nonce_hash) then
    raise exception 'protected_release_nonce_replayed';
  end if;

  insert into public.protected_release_authorizations(
    desktop_session_id,device_identity_id,user_id,request_nonce_hash,app_version,
    release_sequence,integrity_digest,module_index_digest
  ) values (
    v_session.id,v_identity.id,v_session.user_id,p_request_nonce_hash,p_version,
    p_sequence,p_integrity_digest,p_index_digest
  );
  update public.desktop_sessions set last_seen_at=now() where id=v_session.id;
  update public.device_identities set last_seen_at=now() where id=v_identity.id;

  return jsonb_build_object(
    'allowed',true,'userId',v_session.user_id,'sessionId',v_session.id,
    'deviceIdentityId',v_identity.id
  );
end;
$$;

revoke all on function public.paxinbot_authorize_protected_release(text,text,integer,text,text,text) from public,anon,authenticated;
grant execute on function public.paxinbot_authorize_protected_release(text,text,integer,text,text,text) to service_role;

