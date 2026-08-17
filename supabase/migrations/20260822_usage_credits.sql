-- Paxinbot: créditos de uso consumidos somente com o aplicativo conectado.
-- Execute depois de todas as migrations até 20260821.

create table if not exists public.usage_grants (
  id uuid primary key default extensions.gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  total_seconds integer not null check (total_seconds between 60 and 315360000),
  remaining_seconds integer not null check (remaining_seconds between 0 and 315360000),
  status text not null default 'available' check (status in ('available','active','exhausted','revoked')),
  source text not null default 'manual',
  granted_by uuid references auth.users(id) on delete set null,
  activated_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint usage_grant_balance check (remaining_seconds <= total_seconds),
  constraint usage_grant_activation check (
    (status = 'available' and activated_at is null and revoked_at is null)
    or (status = 'active' and activated_at is not null and revoked_at is null and remaining_seconds > 0)
    or (status = 'exhausted' and activated_at is not null and revoked_at is null and remaining_seconds = 0)
    or (status = 'revoked' and revoked_at is not null)
  )
);

create unique index if not exists usage_grants_one_active_per_user
  on public.usage_grants(user_id) where status = 'active';
create index if not exists usage_grants_user_status_idx
  on public.usage_grants(user_id, status, created_at desc);

alter table public.usage_grants enable row level security;
revoke all on table public.usage_grants from public, anon, authenticated;
drop policy if exists "usage_grant_owner_read" on public.usage_grants;
create policy "usage_grant_owner_read" on public.usage_grants
  for select to authenticated using (user_id = auth.uid());
grant select on table public.usage_grants to authenticated;

alter table public.desktop_sessions
  add column if not exists usage_grant_id uuid references public.usage_grants(id) on delete set null;
alter table public.orders
  add column if not exists usage_grant_id uuid references public.usage_grants(id) on delete set null;
create index if not exists desktop_sessions_usage_grant_idx
  on public.desktop_sessions(usage_grant_id, revoked_at);

create or replace function public.paxinbot_active_entitlement(p_user_id uuid)
returns table(kind text, expires_at timestamptz, source text)
language sql stable security definer set search_path = public as $$
  select candidate.kind, candidate.expires_at, candidate.source
  from (
    select e.kind, e.expires_at, e.source,
      case e.kind when 'lifetime' then 0 else 1 end as priority
    from public.entitlements e
    join public.profiles p on p.id = e.user_id
    where e.user_id = p_user_id and p.disabled_at is null
      and e.status = 'active' and e.starts_at <= now()
      and (e.expires_at is null or e.expires_at > now())
    union all
    select 'usage'::text, null::timestamptz, 'usage:' || g.id::text, 2
    from public.usage_grants g
    join public.profiles p on p.id = g.user_id
    where g.user_id = p_user_id and p.disabled_at is null
      and g.status = 'active' and g.remaining_seconds > 0
  ) candidate
  order by candidate.priority, candidate.expires_at desc nulls first
  limit 1;
$$;

create or replace function public.paxinbot_get_my_access()
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare
  v_access record;
  v_grant public.usage_grants%rowtype;
  v_available public.usage_grants%rowtype;
  v_result jsonb;
begin
  if auth.uid() is null then raise exception 'not_authenticated'; end if;
  select * into v_access from public.paxinbot_active_entitlement(auth.uid());
  select * into v_available from public.usage_grants
    where user_id = auth.uid() and status = 'available'
    order by created_at limit 1;

  if found then
    v_result := jsonb_build_object('availableGrant', jsonb_build_object(
      'id', v_available.id, 'totalSeconds', v_available.total_seconds,
      'remainingSeconds', v_available.remaining_seconds, 'createdAt', v_available.created_at
    ));
  else
    v_result := jsonb_build_object('availableGrant', null);
  end if;

  if v_access.kind is null then
    return v_result || jsonb_build_object('active', false, 'kind', null, 'expiresAt', null);
  end if;

  if v_access.kind = 'usage' then
    select * into v_grant from public.usage_grants
      where id = substring(v_access.source from 7)::uuid;
    return v_result || jsonb_build_object(
      'active', true, 'kind', 'usage', 'expiresAt', null, 'source', v_access.source,
      'grantId', v_grant.id, 'totalSeconds', v_grant.total_seconds,
      'remainingSeconds', v_grant.remaining_seconds, 'activatedAt', v_grant.activated_at
    );
  end if;

  return v_result || jsonb_build_object(
    'active', true, 'kind', v_access.kind, 'expiresAt', v_access.expires_at, 'source', v_access.source
  );
end;
$$;

create or replace function public.paxinbot_list_my_usage_grants()
returns jsonb language plpgsql stable security definer set search_path = public as $$
begin
  if auth.uid() is null then raise exception 'not_authenticated'; end if;
  return coalesce((select jsonb_agg(row_to_json(x)) from (
    select id, total_seconds as "totalSeconds", remaining_seconds as "remainingSeconds",
      status, source, activated_at as "activatedAt", created_at as "createdAt"
    from public.usage_grants where user_id = auth.uid()
    order by case status when 'active' then 0 when 'available' then 1 else 2 end, created_at
  ) x), '[]'::jsonb);
end;
$$;

create or replace function public.paxinbot_activate_usage_grant(p_grant_id uuid)
returns jsonb language plpgsql security definer set search_path = public as $$
declare v_grant public.usage_grants%rowtype;
begin
  if auth.uid() is null then raise exception 'not_authenticated'; end if;
  perform pg_advisory_xact_lock(hashtextextended(auth.uid()::text, 0));

  select * into v_grant from public.usage_grants
    where id = p_grant_id and user_id = auth.uid() for update;
  if not found then raise exception 'usage_grant_not_found'; end if;
  if v_grant.status = 'active' then
    return jsonb_build_object('id',v_grant.id,'status','active','remainingSeconds',v_grant.remaining_seconds);
  end if;
  if v_grant.status <> 'available' or v_grant.remaining_seconds <= 0 then
    raise exception 'usage_grant_unavailable';
  end if;
  if exists (
    select 1 from public.entitlements e where e.user_id = auth.uid()
      and e.status = 'active' and e.starts_at <= now()
      and (e.expires_at is null or e.expires_at > now())
  ) then raise exception 'existing_access_must_finish'; end if;
  if exists (select 1 from public.usage_grants where user_id = auth.uid() and status = 'active') then
    raise exception 'usage_grant_already_active';
  end if;

  update public.usage_grants set status='active', activated_at=now(), updated_at=now()
    where id=v_grant.id returning * into v_grant;
  insert into public.audit_events(user_id,event_type,metadata)
    values(auth.uid(),'usage.activated',jsonb_build_object('grantId',v_grant.id,'totalSeconds',v_grant.total_seconds));
  return jsonb_build_object('id',v_grant.id,'status',v_grant.status,
    'totalSeconds',v_grant.total_seconds,'remainingSeconds',v_grant.remaining_seconds,
    'activatedAt',v_grant.activated_at);
end;
$$;

create or replace function public.paxinbot_owner_grant_usage(
  p_email text, p_total_seconds integer, p_source text default 'owner-panel'
)
returns jsonb language plpgsql security definer set search_path = public as $$
declare v_user_id uuid; v_grant public.usage_grants%rowtype;
begin
  perform public.paxinbot_require_owner();
  if p_total_seconds not between 60 and 315360000 then raise exception 'invalid_usage_duration'; end if;
  select id into v_user_id from auth.users where lower(email)=lower(trim(p_email));
  if v_user_id is null then raise exception 'user_not_found'; end if;
  insert into public.usage_grants(user_id,total_seconds,remaining_seconds,source,granted_by)
    values(v_user_id,p_total_seconds,p_total_seconds,left(coalesce(p_source,'owner-panel'),80),auth.uid())
    returning * into v_grant;
  insert into public.audit_events(user_id,event_type,metadata)
    values(auth.uid(),'owner.usage_granted',jsonb_build_object('targetUserId',v_user_id,'grantId',v_grant.id,'totalSeconds',p_total_seconds));
  return jsonb_build_object('id',v_grant.id,'status',v_grant.status,'totalSeconds',v_grant.total_seconds);
end;
$$;

create or replace function public.paxinbot_owner_list_users(p_query text default '')
returns jsonb language plpgsql security definer set search_path = public, auth, pg_temp as $$
begin
  perform public.paxinbot_require_owner();
  return coalesce((select jsonb_agg(row_to_json(x)) from (
    select u.id,u.email,p.disabled_at,u.created_at,
      case
        when a.kind='usage' then jsonb_build_object('kind','usage','expiresAt',null,'source',a.source,
          'grantId',g.id,'totalSeconds',g.total_seconds,'remainingSeconds',g.remaining_seconds,'activatedAt',g.activated_at)
        when a.kind is not null then jsonb_build_object('kind',a.kind,'expiresAt',a.expires_at,'source',a.source)
        else null
      end as access,
      coalesce((select sum(ug.remaining_seconds) from public.usage_grants ug where ug.user_id=u.id and ug.status='available'),0) as "availableCreditSeconds",
      (select count(*) from public.desktop_sessions s where s.user_id=u.id and s.revoked_at is null and s.last_seen_at > now() - interval '30 seconds')::int as "activeSessions",
      (select count(*) from public.device_account_bindings dab where dab.user_id=u.id)::int as "deviceCount"
    from auth.users u join public.profiles p on p.id=u.id
    left join lateral (select * from public.paxinbot_active_entitlement(u.id)) a on true
    left join lateral (select ug.* from public.usage_grants ug where ug.id=case
      when a.kind='usage' and a.source ~ '^usage:[0-9a-fA-F-]{36}$' then substring(a.source from 7)::uuid
      else null end) g on true
    where lower(u.email) like '%' || lower(left(coalesce(p_query,''),120)) || '%'
    order by u.created_at desc limit 100
  ) x),'[]'::jsonb);
end;
$$;

create or replace function public.paxinbot_owner_overview()
returns jsonb language plpgsql security definer set search_path = public, auth, pg_temp as $$
begin
  perform public.paxinbot_require_owner();

  -- Atualiza pedidos pendentes antigos para expirados
  update public.orders
  set status = 'expired', provider_status = 'expired', updated_at = now()
  where status = 'pending' and created_at < now() - interval '1 hour';

  return jsonb_build_object(
    'customers',(select count(*) from public.profiles where role='customer' and disabled_at is null),
    'activeAccesses',(select count(*) from public.entitlements where status='active' and starts_at<=now() and (expires_at is null or expires_at>now()))
      +(select count(*) from public.usage_grants where status='active' and remaining_seconds>0),
    'availableUsageGrants',(select count(*) from public.usage_grants where status='available'),
    'activeProducts',(select count(*) from public.products where active),
    'activeCoupons',(select count(*) from public.coupons where active and (expires_at is null or expires_at>now())),
    'paidOrders',(select count(*) from public.orders where status='paid'),
    'pendingOrders',(select count(*) from public.orders where status='pending' and created_at >= now() - interval '1 hour'),
    'revenueCents',(select coalesce(sum(amount_cents),0) from public.orders where status='paid'),
    'openTickets',(select count(*) from public.support_tickets where status in ('open','in_progress')),
    'lastPaymentEventAt',(select max(created_at) from public.audit_events where event_type like 'payment.%')
  );
end;
$$;

create or replace function public.paxinbot_owner_kick_user(p_user_id uuid)
returns jsonb language plpgsql security definer set search_path = public, auth, pg_temp as $$
begin
  perform public.paxinbot_require_owner();
  if p_user_id is null then raise exception 'invalid_user'; end if;
  update public.desktop_sessions
  set revoked_at = now()
  where user_id = p_user_id and revoked_at is null;
  insert into public.audit_events (user_id, event_type, metadata)
  values (auth.uid(), 'owner.user_kicked', jsonb_build_object('targetUserId', p_user_id));
  return jsonb_build_object('ok', true);
end;
$$;

create or replace function public.paxinbot_owner_set_user_ban(p_user_id uuid, p_banned boolean, p_reason text default null)
returns jsonb language plpgsql security definer set search_path = public, auth, pg_temp as $$
begin
  perform public.paxinbot_require_owner();
  if p_user_id is null then raise exception 'invalid_user'; end if;
  if p_banned then
    update public.profiles set disabled_at = coalesce(disabled_at, now()) where id = p_user_id;
    update public.entitlements set status = 'revoked', revoked_at = now() where user_id = p_user_id and status = 'active';
    update public.usage_grants set status = 'revoked', revoked_at = now() where user_id = p_user_id and status in ('available', 'active');
    update public.desktop_sessions set revoked_at = now() where user_id = p_user_id and revoked_at is null;
    insert into public.audit_events (user_id, event_type, metadata)
    values (auth.uid(), 'owner.user_banned', jsonb_build_object('targetUserId', p_user_id, 'reason', p_reason));
  else
    update public.profiles set disabled_at = null where id = p_user_id;
    insert into public.audit_events (user_id, event_type, metadata)
    values (auth.uid(), 'owner.user_unbanned', jsonb_build_object('targetUserId', p_user_id));
  end if;
  return jsonb_build_object('ok', true);
end;
$$;

create or replace function public.paxinbot_owner_reset_user_devices(p_user_id uuid)
returns jsonb language plpgsql security definer set search_path = public, auth, pg_temp as $$
begin
  perform public.paxinbot_require_owner();
  if p_user_id is null then raise exception 'invalid_user'; end if;
  delete from public.device_account_bindings where user_id = p_user_id;
  update public.desktop_sessions set revoked_at = now() where user_id = p_user_id and revoked_at is null;
  insert into public.audit_events (user_id, event_type, metadata)
  values (auth.uid(), 'owner.user_devices_reset', jsonb_build_object('targetUserId', p_user_id));
  return jsonb_build_object('ok', true);
end;
$$;

create or replace function public.paxinbot_owner_revoke_access(p_user_id uuid)
returns void language plpgsql security definer set search_path = public as $$
begin
  perform public.paxinbot_require_owner();
  update public.entitlements set status='revoked',revoked_at=coalesce(revoked_at,now())
    where user_id=p_user_id and status='active';
  update public.usage_grants set status='revoked',revoked_at=now(),updated_at=now()
    where user_id=p_user_id and status in ('available','active');
  update public.desktop_sessions set revoked_at=now()
    where user_id=p_user_id and revoked_at is null;
  insert into public.audit_events(user_id,event_type,metadata)
    values(auth.uid(),'owner.access_revoked',jsonb_build_object('targetUserId',p_user_id));
end;
$$;

create or replace function public.paxinbot_device_poll_v2(p_request_id uuid,p_secret_hash text)
returns jsonb language plpgsql security definer set search_path = public as $$
declare
  v_device public.device_authorizations%rowtype; v_access record;
  v_grant public.usage_grants%rowtype; v_token text; v_expires timestamptz;
begin
  if p_secret_hash !~ '^[a-f0-9]{64}$' then raise exception 'invalid_device_request'; end if;
  select * into v_device from public.device_authorizations
    where id=p_request_id and secret_hash=p_secret_hash for update;
  if not found then raise exception 'device_request_invalid'; end if;
  if v_device.expires_at<=now() then raise exception 'device_expired'; end if;
  if v_device.consumed_at is not null then raise exception 'device_consumed'; end if;
  if v_device.denied_at is not null then raise exception 'device_denied'; end if;
  if v_device.last_polled_at is not null and v_device.last_polled_at>now()-interval '2 seconds' then raise exception 'device_poll_limit'; end if;
  update public.device_authorizations set last_polled_at=now(),poll_count=poll_count+1 where id=v_device.id;
  if v_device.poll_count>=180 then raise exception 'device_poll_limit'; end if;
  if v_device.approved_user_id is null then return jsonb_build_object('status','pending','intervalMs',5000); end if;

  select * into v_access from public.paxinbot_active_entitlement(v_device.approved_user_id);
  if not found then raise exception 'no_active_access'; end if;
  if v_access.kind='usage' then
    select * into v_grant from public.usage_grants
      where id=substring(v_access.source from 7)::uuid and status='active' for update;
    if not found or v_grant.remaining_seconds<=0 then raise exception 'no_active_access'; end if;
    update public.desktop_sessions set revoked_at=now()
      where usage_grant_id=v_grant.id and revoked_at is null;
  end if;

  v_token:=encode(extensions.gen_random_bytes(32),'hex'); v_expires:=now()+interval '7 days';
  insert into public.desktop_sessions(token_hash,user_id,device_name,app_version,expires_at,usage_grant_id)
    values(encode(extensions.digest(v_token,'sha256'),'hex'),v_device.approved_user_id,v_device.device_name,
      v_device.app_version,v_expires,case when v_access.kind='usage' then v_grant.id else null end);
  update public.device_authorizations set consumed_at=now() where id=v_device.id;
  insert into public.audit_events(user_id,event_type,metadata)
    values(v_device.approved_user_id,'device.signed_in',jsonb_build_object('deviceName',v_device.device_name,'appVersion',v_device.app_version));
  return jsonb_build_object('status','approved','desktopToken',v_token,'sessionExpiresAt',v_expires,
    'entitlement',jsonb_build_object('active',true,'kind',v_access.kind,'expiresAt',v_access.expires_at,
      'source',v_access.source,'grantId',v_grant.id,'totalSeconds',v_grant.total_seconds,'remainingSeconds',v_grant.remaining_seconds));
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
    -- Se um acesso vitalício ou legado foi concedido depois da ativação do
    -- crédito, ele tem prioridade e o saldo permanece pausado para uso futuro.
    select e.kind,e.expires_at,e.source into v_access
      from public.entitlements e join public.profiles p on p.id=e.user_id
      where e.user_id=v_session.user_id and p.disabled_at is null and e.status='active'
        and e.starts_at<=now() and (e.expires_at is null or e.expires_at>now())
      order by case e.kind when 'lifetime' then 0 else 1 end,e.expires_at desc nulls first limit 1;
    if found then
      select email into v_email from auth.users where id=v_session.user_id;
      update public.desktop_sessions set usage_grant_id=null,last_seen_at=now() where id=v_session.id;
      return jsonb_build_object('active',true,'user',jsonb_build_object('id',v_session.user_id,'email',v_email),
        'deviceName',v_session.device_name,'sessionExpiresAt',v_session.expires_at,
        'entitlement',jsonb_build_object('active',true,'kind',v_access.kind,'expiresAt',v_access.expires_at,'source',v_access.source));
    end if;
    select * into v_grant from public.usage_grants where id=v_session.usage_grant_id for update;
    if not found or v_grant.status<>'active' or v_grant.remaining_seconds<=0 then
      update public.desktop_sessions set revoked_at=now() where id=v_session.id;
      return jsonb_build_object('active',false,'reason','usage_unavailable');
    end if;
    if v_session.last_seen_at>=now()-interval '60 seconds' then
      v_elapsed:=least(15,greatest(0,floor(extract(epoch from (now()-v_session.last_seen_at)))::integer));
    end if;
    if v_elapsed>=v_grant.remaining_seconds then
      update public.usage_grants set remaining_seconds=0,status='exhausted',updated_at=now() where id=v_grant.id;
      update public.desktop_sessions set revoked_at=now(),last_seen_at=now() where usage_grant_id=v_grant.id and revoked_at is null;
      insert into public.audit_events(user_id,event_type,metadata)
        values(v_session.user_id,'usage.exhausted',jsonb_build_object('grantId',v_grant.id));
      return jsonb_build_object('active',false,'reason','usage_exhausted');
    end if;
    update public.usage_grants set remaining_seconds=remaining_seconds-v_elapsed,updated_at=now()
      where id=v_grant.id returning * into v_grant;
    update public.desktop_sessions set last_seen_at=now() where id=v_session.id;
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
  update public.desktop_sessions set last_seen_at=now() where id=v_session.id;
  return jsonb_build_object('active',true,'user',jsonb_build_object('id',v_session.user_id,'email',v_email),
    'deviceName',v_session.device_name,'sessionExpiresAt',v_session.expires_at,
    'entitlement',jsonb_build_object('active',true,'kind',v_access.kind,'expiresAt',v_access.expires_at,'source',v_access.source));
end;
$$;

create or replace function public.paxinbot_finalize_mercadopago_payment(
  p_payment_id text,p_external_reference text,p_status text,p_amount_cents integer,p_currency text,
  p_provider_payload jsonb default '{}'::jsonb
)
returns jsonb language plpgsql security definer set search_path = public as $$
declare
  v_order public.orders%rowtype; v_product public.products%rowtype;
  v_entitlement_id uuid; v_usage_grant_id uuid; v_email text;
  v_first_approval boolean:=false; v_final_status text:=lower(coalesce(p_status,''));
begin
  if auth.role()<>'service_role' then raise exception 'service_role_required'; end if;
  if p_payment_id is null or char_length(p_payment_id) not between 1 and 120 then raise exception 'invalid_payment'; end if;
  if p_external_reference !~ '^[0-9a-fA-F-]{36}$' then return jsonb_build_object('processed',false,'reason','invalid_reference'); end if;
  select * into v_order from public.orders where external_reference=p_external_reference for update;
  if not found then return jsonb_build_object('processed',false,'reason','order_not_found'); end if;
  perform pg_advisory_xact_lock(hashtextextended(v_order.user_id::text,0));
  select * into v_product from public.products where id=v_order.product_id;
  select email into v_email from auth.users where id=v_order.user_id;

  if v_final_status='approved' then
    if p_amount_cents<>v_order.amount_cents or upper(coalesce(p_currency,''))<>upper(v_order.currency) then
      update public.orders set provider_payment_id=p_payment_id,provider_status='amount_mismatch',
        metadata=metadata||jsonb_build_object('paymentSnapshot',p_provider_payload),updated_at=now() where id=v_order.id;
      insert into public.audit_events(user_id,event_type,metadata) values(v_order.user_id,'payment.amount_mismatch',jsonb_build_object('orderId',v_order.id,'paymentId',p_payment_id));
      return jsonb_build_object('processed',false,'reason','amount_mismatch');
    end if;
    if v_order.status='paid' and v_order.provider_payment_id=p_payment_id then return jsonb_build_object('processed',false,'reason','already_paid','orderId',v_order.id); end if;
    if exists(select 1 from public.orders where provider_payment_id=p_payment_id and id<>v_order.id) then return jsonb_build_object('processed',false,'reason','payment_already_used'); end if;

    v_entitlement_id:=v_order.entitlement_id; v_usage_grant_id:=v_order.usage_grant_id;
    if v_entitlement_id is null and v_usage_grant_id is null then
      if v_product.access_kind='lifetime' then
        insert into public.entitlements(user_id,kind,expires_at,source)
          values(v_order.user_id,'lifetime',null,left('mercado-pago:'||v_order.id::text,50)) returning id into v_entitlement_id;
      else
        insert into public.usage_grants(user_id,total_seconds,remaining_seconds,source)
          values(v_order.user_id,v_product.duration_minutes*60,v_product.duration_minutes*60,left('mercado-pago:'||v_order.id::text,80))
          returning id into v_usage_grant_id;
      end if;
      v_first_approval:=true;
    end if;
    update public.orders set status='paid',provider_payment_id=p_payment_id,provider_status=v_final_status,
      entitlement_id=v_entitlement_id,usage_grant_id=v_usage_grant_id,paid_at=coalesce(paid_at,now()),updated_at=now(),
      metadata=metadata||jsonb_build_object('paymentSnapshot',p_provider_payload) where id=v_order.id;
    if v_first_approval and v_order.coupon_id is not null then update public.coupons set redemptions=redemptions+1,updated_at=now() where id=v_order.coupon_id; end if;
    if v_first_approval then insert into public.audit_events(user_id,event_type,metadata)
      values(v_order.user_id,'payment.approved',jsonb_build_object('orderId',v_order.id,'productId',v_order.product_id,'usageGrantId',v_usage_grant_id)); end if;
  elsif v_final_status in ('refunded','charged_back') then
    update public.orders set status=case when v_final_status='charged_back' then 'chargeback' else 'refunded' end,
      provider_payment_id=p_payment_id,provider_status=v_final_status,updated_at=now(),metadata=metadata||jsonb_build_object('paymentSnapshot',p_provider_payload) where id=v_order.id;
    if v_order.entitlement_id is not null then update public.entitlements set status='revoked',revoked_at=coalesce(revoked_at,now()) where id=v_order.entitlement_id; end if;
    if v_order.usage_grant_id is not null then update public.usage_grants set status='revoked',revoked_at=coalesce(revoked_at,now()),updated_at=now() where id=v_order.usage_grant_id and status<>'revoked'; end if;
    update public.desktop_sessions set revoked_at=now() where user_id=v_order.user_id and revoked_at is null;
    insert into public.audit_events(user_id,event_type,metadata) values(v_order.user_id,'payment.'||v_final_status,jsonb_build_object('orderId',v_order.id));
  elsif v_final_status in ('rejected','cancelled') and v_order.status<>'paid' then
    update public.orders set status='cancelled',provider_payment_id=p_payment_id,provider_status=v_final_status,updated_at=now(),metadata=metadata||jsonb_build_object('paymentSnapshot',p_provider_payload) where id=v_order.id;
  else
    update public.orders set provider_payment_id=p_payment_id,provider_status=v_final_status,updated_at=now(),metadata=metadata||jsonb_build_object('paymentSnapshot',p_provider_payload) where id=v_order.id and status='pending';
  end if;
  return jsonb_build_object('processed',v_first_approval,'orderId',v_order.id,'status',case when v_final_status='approved' then 'paid' else v_final_status end,
    'email',v_email,'productName',v_product.name,'usageGrantId',v_usage_grant_id,'amountCents',v_order.amount_cents,'currency',v_order.currency);
end;
$$;

revoke all on function public.paxinbot_active_entitlement(uuid) from public,anon,authenticated;
revoke all on function public.paxinbot_list_my_usage_grants() from public;
revoke all on function public.paxinbot_activate_usage_grant(uuid) from public;
revoke all on function public.paxinbot_owner_grant_usage(text,integer,text) from public;
revoke all on function public.paxinbot_device_poll_v2(uuid,text) from public,anon,authenticated;
revoke all on function public.paxinbot_desktop_session_v2(text) from public,anon,authenticated;
revoke all on function public.paxinbot_finalize_mercadopago_payment(text,text,text,integer,text,jsonb) from public;
grant execute on function public.paxinbot_get_my_access() to authenticated;
grant execute on function public.paxinbot_list_my_usage_grants() to authenticated;
grant execute on function public.paxinbot_activate_usage_grant(uuid) to authenticated;
grant execute on function public.paxinbot_owner_grant_usage(text,integer,text) to authenticated;
grant execute on function public.paxinbot_device_poll_v2(uuid,text) to service_role;
grant execute on function public.paxinbot_desktop_session_v2(text) to service_role;
grant execute on function public.paxinbot_finalize_mercadopago_payment(text,text,text,integer,text,jsonb) to service_role;
