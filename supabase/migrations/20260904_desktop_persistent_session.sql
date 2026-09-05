begin;

create or replace function public.paxinbot_desktop_session_v4(p_token_hash text, p_action text default 'session')
returns jsonb language plpgsql security definer set search_path=public,auth,pg_temp as $$
declare
  v_session public.desktop_sessions%rowtype;
  v_identity public.device_identities%rowtype;
  v_grant public.usage_grants%rowtype;
  v_access record;
  v_profile jsonb;
  v_user jsonb;
  v_result jsonb;
  v_elapsed integer := 0;
begin
  if auth.role() <> 'service_role' then raise exception 'service_role_required'; end if;
  if p_action is null or p_action not in ('session','profile','pause','logout') then raise exception 'invalid_session_action'; end if;
  if p_token_hash is null or p_token_hash !~ '^[a-f0-9]{64}$' then
    return jsonb_build_object('active',false,'reason','session_invalid');
  end if;
  select * into v_session from public.desktop_sessions where token_hash=p_token_hash for update;
  if not found then return jsonb_build_object('active',false,'reason','session_invalid'); end if;

  if p_action='logout' then
    if v_session.revoked_at is null and v_session.usage_grant_id is not null and v_session.usage_paused_at is null then
      select * into v_grant from public.usage_grants
        where id=v_session.usage_grant_id and user_id=v_session.user_id for update;
      if found and v_grant.status='active' and v_grant.remaining_seconds>0 then
        if v_session.last_seen_at>=now()-interval '60 seconds' then
          v_elapsed:=least(15,greatest(0,floor(extract(epoch from (now()-v_session.last_seen_at)))::integer));
        end if;
        update public.usage_grants
          set remaining_seconds=greatest(0,remaining_seconds-v_elapsed),
            status=case when remaining_seconds<=v_elapsed then 'exhausted' else status end,
            updated_at=now()
          where id=v_grant.id;
      end if;
    end if;
    update public.desktop_sessions
      set revoked_at=coalesce(revoked_at,now()),usage_paused_at=coalesce(usage_paused_at,now())
      where id=v_session.id;
    return jsonb_build_object('active',false,'loggedOut',true,'paused',true);
  end if;

  if v_session.revoked_at is not null or v_session.expires_at is null or v_session.expires_at<=now() or v_session.device_identity_id is null then
    return jsonb_build_object('active',false,'reason','session_invalid');
  end if;
  select * into v_identity from public.device_identities where id=v_session.device_identity_id for update;
  if not found or v_identity.banned_at is not null
    or exists(select 1 from public.device_identities where fingerprint_hash=v_identity.fingerprint_hash and banned_at is not null) then
    update public.desktop_sessions set revoked_at=coalesce(revoked_at,now()) where id=v_session.id;
    return jsonb_build_object('active',false,'reason','device_banned');
  end if;
  if exists(select 1 from public.security_risk_state where device_identity_id=v_identity.id and restricted_until>now()) then
    update public.desktop_sessions set revoked_at=coalesce(revoked_at,now()) where id=v_session.id;
    return jsonb_build_object('active',false,'reason','risk_reauthentication_required');
  end if;
  select jsonb_build_object('nickname',coalesce(nullif(btrim(profile.display_name),''),split_part(account.email,'@',1),''),
      'avatarUrl',case when to_jsonb(profile) ? 'avatar_data' then to_jsonb(profile)->>'avatar_data'
        else coalesce(nullif(to_jsonb(profile)->>'avatar_url',''),nullif(account.raw_user_meta_data->>'avatar_url',''),nullif(account.raw_user_meta_data->>'picture','')) end),
    jsonb_build_object('id',account.id,'email',account.email)
    into v_profile,v_user
    from public.profiles profile join auth.users account on account.id=profile.id
    where profile.id=v_session.user_id and profile.disabled_at is null;
  if not found then
    update public.desktop_sessions set revoked_at=coalesce(revoked_at,now()) where id=v_session.id;
    return jsonb_build_object('active',false,'reason','account_disabled');
  end if;
  select * into v_access from public.paxinbot_active_entitlement(v_session.user_id);
  if not found then
    update public.desktop_sessions set revoked_at=coalesce(revoked_at,now()) where id=v_session.id;
    return jsonb_build_object('active',false,'reason','no_active_access');
  end if;
  if v_access.kind='usage' then
    select * into v_grant from public.usage_grants
      where id=coalesce(v_session.usage_grant_id,substring(v_access.source from 7)::uuid)
        and user_id=v_session.user_id and status='active' and remaining_seconds>0;
    if not found then
      update public.desktop_sessions set revoked_at=coalesce(revoked_at,now()) where id=v_session.id;
      return jsonb_build_object('active',false,'reason','usage_unavailable');
    end if;
  end if;

  if p_action='profile' then
    v_result:=jsonb_build_object('active',true,'user',v_user,'deviceName',v_session.device_name,
      'entitlement',jsonb_build_object('active',true,'kind',v_access.kind,'expiresAt',v_access.expires_at,
        'source',case when v_access.kind='usage' then v_grant.source else v_access.source end));
    if v_access.kind='usage' then
      v_result:=jsonb_set(v_result,'{entitlement}',(v_result->'entitlement') || jsonb_build_object(
        'grantId',v_grant.id,'totalSeconds',v_grant.total_seconds,'remainingSeconds',v_grant.remaining_seconds));
    end if;
  elsif p_action='pause' then
    v_result:=public.paxinbot_pause_desktop_usage(p_token_hash);
  else
    if v_access.kind='usage' and v_session.usage_grant_id is null then
      update public.desktop_sessions set usage_grant_id=v_grant.id,usage_paused_at=now() where id=v_session.id;
    end if;
    v_result:=public.paxinbot_desktop_session_v2(p_token_hash);
  end if;
  if v_result->>'active' is distinct from 'true' then return v_result; end if;
  update public.desktop_sessions set expires_at=now()+interval '30 days' where id=v_session.id returning expires_at into v_session.expires_at;
  update public.device_identities set last_seen_at=now() where id=v_identity.id;
  return v_result || jsonb_build_object('profile',v_profile,'sessionExpiresAt',v_session.expires_at);
end;
$$;

create or replace function public.paxinbot_device_poll_v4(p_request_id uuid,p_secret_hash text)
returns jsonb language plpgsql security definer set search_path=public,auth,pg_temp as $$
declare v_result jsonb; v_state jsonb; v_token_hash text;
begin
  if auth.role()<>'service_role' then raise exception 'service_role_required'; end if;
  v_result:=public.paxinbot_device_poll_v3(p_request_id,p_secret_hash);
  if v_result->>'status'='approved' then
    v_token_hash:=encode(extensions.digest(v_result->>'desktopToken','sha256'),'hex');
    update public.desktop_sessions set usage_paused_at=now(),expires_at=now()+interval '30 days' where token_hash=v_token_hash;
    v_state:=public.paxinbot_desktop_session_v4(v_token_hash,'profile');
    if v_state->>'active' is distinct from 'true' then
      return jsonb_build_object('status','denied','active',false,'reason',v_state->>'reason');
    end if;
    return v_result || jsonb_build_object('profile',v_state->'profile','sessionExpiresAt',v_state->'sessionExpiresAt','entitlement',v_state->'entitlement');
  end if;
  return v_result;
end;
$$;

revoke all on function public.paxinbot_desktop_session_v4(text,text) from public,anon,authenticated;
revoke all on function public.paxinbot_device_poll_v4(uuid,text) from public,anon,authenticated;
grant execute on function public.paxinbot_desktop_session_v4(text,text) to service_role;
grant execute on function public.paxinbot_device_poll_v4(uuid,text) to service_role;

commit;
