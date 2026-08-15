-- Paxinbot: recursos incrementais para os portais do cliente e proprietário.
-- Execute após 20260815_paxinbot_access.sql.

alter table public.profiles add column if not exists display_name text;
alter table public.profiles drop constraint if exists profiles_display_name_check;
alter table public.profiles add constraint profiles_display_name_check
  check (display_name is null or char_length(display_name) between 2 and 80);

create or replace function public.paxinbot_get_my_account()
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v_result jsonb;
begin
  if auth.uid() is null then raise exception 'not_authenticated'; end if;
  select jsonb_build_object(
    'profile', jsonb_build_object(
      'displayName', coalesce(p.display_name, split_part(u.email, '@', 1)),
      'email', u.email,
      'createdAt', u.created_at
    ),
    'activeDevices', (select count(*) from public.desktop_sessions s where s.user_id = auth.uid() and s.revoked_at is null and s.expires_at > now()),
    'orders', (select count(*) from public.orders o where o.user_id = auth.uid())
  ) into v_result
  from auth.users u join public.profiles p on p.id = u.id
  where u.id = auth.uid();
  return coalesce(v_result, '{}'::jsonb);
end;
$$;

create or replace function public.paxinbot_list_my_devices()
returns jsonb language plpgsql stable security definer set search_path = public as $$
begin
  if auth.uid() is null then raise exception 'not_authenticated'; end if;
  return coalesce((select jsonb_agg(row_to_json(x)) from (
    select s.id, s.device_name as "deviceName", s.created_at as "createdAt",
      s.last_seen_at as "lastSeenAt", s.expires_at as "expiresAt",
      case when s.revoked_at is not null then 'revoked' when s.expires_at <= now() then 'expired' else 'active' end as status
    from public.desktop_sessions s
    where s.user_id = auth.uid()
    order by s.last_seen_at desc
    limit 50
  ) x), '[]'::jsonb);
end;
$$;

create or replace function public.paxinbot_revoke_my_device(p_session_id uuid)
returns void language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then raise exception 'not_authenticated'; end if;
  update public.desktop_sessions set revoked_at = coalesce(revoked_at, now())
  where id = p_session_id and user_id = auth.uid();
  if not found then raise exception 'device_not_found'; end if;
  insert into public.audit_events (user_id, event_type, metadata)
  values (auth.uid(), 'device.revoked', jsonb_build_object('sessionId', p_session_id));
end;
$$;

create or replace function public.paxinbot_revoke_all_my_devices()
returns integer language plpgsql security definer set search_path = public as $$
declare v_count integer;
begin
  if auth.uid() is null then raise exception 'not_authenticated'; end if;
  update public.desktop_sessions set revoked_at = now()
  where user_id = auth.uid() and revoked_at is null and expires_at > now();
  get diagnostics v_count = row_count;
  insert into public.audit_events (user_id, event_type, metadata)
  values (auth.uid(), 'device.revoked_all', jsonb_build_object('count', v_count));
  return v_count;
end;
$$;

create or replace function public.paxinbot_update_my_profile(p_display_name text)
returns jsonb language plpgsql security definer set search_path = public as $$
declare v_name text := nullif(trim(p_display_name), '');
begin
  if auth.uid() is null then raise exception 'not_authenticated'; end if;
  if v_name is null or char_length(v_name) not between 2 and 80 then raise exception 'invalid_display_name'; end if;
  update public.profiles set display_name = v_name where id = auth.uid();
  insert into public.audit_events (user_id, event_type) values (auth.uid(), 'account.profile_updated');
  return jsonb_build_object('displayName', v_name);
end;
$$;

create or replace function public.paxinbot_list_my_orders()
returns jsonb language plpgsql stable security definer set search_path = public as $$
begin
  if auth.uid() is null then raise exception 'not_authenticated'; end if;
  return coalesce((select jsonb_agg(row_to_json(x)) from (
    select o.id, o.amount_cents as "amountCents", o.currency, o.status,
      o.created_at as "createdAt", o.paid_at as "paidAt", p.name as "productName"
    from public.orders o left join public.products p on p.id = o.product_id
    where o.user_id = auth.uid()
    order by o.created_at desc limit 100
  ) x), '[]'::jsonb);
end;
$$;

create or replace function public.paxinbot_owner_list_orders()
returns jsonb language plpgsql stable security definer set search_path = public as $$
begin
  perform public.paxinbot_require_owner();
  return coalesce((select jsonb_agg(row_to_json(x)) from (
    select o.id, u.email, p.name as "productName", o.amount_cents as "amountCents",
      o.currency, o.status, o.payment_provider as "paymentProvider",
      o.created_at as "createdAt", o.paid_at as "paidAt"
    from public.orders o
    join auth.users u on u.id = o.user_id
    left join public.products p on p.id = o.product_id
    order by o.created_at desc limit 200
  ) x), '[]'::jsonb);
end;
$$;

create or replace function public.paxinbot_owner_list_audit()
returns jsonb language plpgsql stable security definer set search_path = public as $$
begin
  perform public.paxinbot_require_owner();
  return coalesce((select jsonb_agg(row_to_json(x)) from (
    select a.id, u.email, a.event_type as "eventType", a.created_at as "createdAt", a.metadata
    from public.audit_events a left join auth.users u on u.id = a.user_id
    order by a.created_at desc limit 200
  ) x), '[]'::jsonb);
end;
$$;

create or replace function public.paxinbot_owner_revoke_access(p_user_id uuid)
returns void language plpgsql security definer set search_path = public as $$
begin
  perform public.paxinbot_require_owner();
  update public.entitlements set status = 'revoked', revoked_at = now()
  where user_id = p_user_id and status = 'active';
  update public.desktop_sessions set revoked_at = now()
  where user_id = p_user_id and revoked_at is null;
  insert into public.audit_events (user_id, event_type, metadata)
  values (auth.uid(), 'owner.access_revoked', jsonb_build_object('targetUserId', p_user_id));
end;
$$;

revoke all on function public.paxinbot_get_my_account() from public;
revoke all on function public.paxinbot_list_my_devices() from public;
revoke all on function public.paxinbot_revoke_my_device(uuid) from public;
revoke all on function public.paxinbot_revoke_all_my_devices() from public;
revoke all on function public.paxinbot_update_my_profile(text) from public;
revoke all on function public.paxinbot_list_my_orders() from public;
revoke all on function public.paxinbot_owner_list_orders() from public;
revoke all on function public.paxinbot_owner_list_audit() from public;
revoke all on function public.paxinbot_owner_revoke_access(uuid) from public;

grant execute on function public.paxinbot_get_my_account() to authenticated;
grant execute on function public.paxinbot_list_my_devices() to authenticated;
grant execute on function public.paxinbot_revoke_my_device(uuid) to authenticated;
grant execute on function public.paxinbot_revoke_all_my_devices() to authenticated;
grant execute on function public.paxinbot_update_my_profile(text) to authenticated;
grant execute on function public.paxinbot_list_my_orders() to authenticated;
grant execute on function public.paxinbot_owner_list_orders() to authenticated;
grant execute on function public.paxinbot_owner_list_audit() to authenticated;
grant execute on function public.paxinbot_owner_revoke_access(uuid) to authenticated;
