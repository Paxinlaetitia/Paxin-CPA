-- Paxinbot: checkout Mercado Pago, cupons e concessão automática de acesso.
-- Execute depois de 20260815_portals.sql e 20260816_catalog.sql.

alter table public.orders add column if not exists subtotal_cents integer;
alter table public.orders add column if not exists discount_cents integer not null default 0;
alter table public.orders add column if not exists external_reference text;
alter table public.orders add column if not exists provider_preference_id text;
alter table public.orders add column if not exists provider_payment_id text;
alter table public.orders add column if not exists provider_status text;
alter table public.orders add column if not exists entitlement_id uuid references public.entitlements(id) on delete set null;
alter table public.orders add column if not exists metadata jsonb not null default '{}'::jsonb;
alter table public.orders add column if not exists confirmation_sent_at timestamptz;

update public.orders set subtotal_cents = amount_cents where subtotal_cents is null;
alter table public.orders alter column subtotal_cents set not null;

create unique index if not exists orders_external_reference_unique
  on public.orders (external_reference) where external_reference is not null;
create unique index if not exists orders_provider_payment_unique
  on public.orders (provider_payment_id) where provider_payment_id is not null;
create index if not exists orders_user_created_idx on public.orders (user_id, created_at desc);

create or replace function public.paxinbot_prepare_checkout(p_product_id uuid, p_coupon_code text default null)
returns jsonb language plpgsql security definer set search_path = public as $$
declare
  v_user_id uuid := auth.uid();
  v_product public.products%rowtype;
  v_coupon public.coupons%rowtype;
  v_coupon_code text := nullif(upper(trim(coalesce(p_coupon_code, ''))), '');
  v_subtotal integer;
  v_discount integer := 0;
  v_order_id uuid := gen_random_uuid();
  v_email text;
begin
  if v_user_id is null then raise exception 'not_authenticated'; end if;
  if p_product_id is null then raise exception 'invalid_product'; end if;
  if v_coupon_code is not null and v_coupon_code !~ '^[A-Z0-9_-]{3,32}$' then raise exception 'invalid_coupon'; end if;

  select * into v_product from public.products where id = p_product_id and active is true;
  if not found then raise exception 'product_unavailable'; end if;
  if v_product.price_cents <= 0 or v_product.currency <> 'BRL' then raise exception 'product_not_payable'; end if;
  if exists (select 1 from public.entitlements e where e.user_id = v_user_id and e.kind = 'lifetime' and e.status = 'active' and e.starts_at <= now()) then
    raise exception 'lifetime_already_active';
  end if;
  if (select count(*) from public.orders o where o.user_id = v_user_id and o.status = 'pending' and o.created_at > now() - interval '10 minutes') >= 5 then
    raise exception 'checkout_rate_limited';
  end if;

  v_subtotal := v_product.price_cents;
  if v_coupon_code is not null then
    select * into v_coupon from public.coupons c where c.code = v_coupon_code for update;
    if not found or not v_coupon.active
       or (v_coupon.starts_at is not null and v_coupon.starts_at > now())
       or (v_coupon.expires_at is not null and v_coupon.expires_at <= now())
       or (v_coupon.max_redemptions is not null and
           v_coupon.redemptions + (select count(*) from public.orders o where o.coupon_id = v_coupon.id and o.status = 'pending') >= v_coupon.max_redemptions) then
      raise exception 'coupon_unavailable';
    end if;
    if v_coupon.discount_type = 'percent' then
      v_discount := least(v_subtotal, round(v_subtotal * least(v_coupon.discount_value, 100)::numeric / 100)::integer);
    else
      v_discount := least(v_subtotal, v_coupon.discount_value);
    end if;
  end if;
  if v_subtotal - v_discount <= 0 then raise exception 'zero_value_checkout'; end if;

  select email into v_email from auth.users where id = v_user_id;
  insert into public.orders (
    id, user_id, product_id, coupon_id, subtotal_cents, discount_cents,
    amount_cents, currency, status, payment_provider, external_reference, metadata
  ) values (
    v_order_id, v_user_id, v_product.id, v_coupon.id, v_subtotal, v_discount,
    v_subtotal - v_discount, v_product.currency, 'pending', 'mercado_pago', v_order_id::text,
    jsonb_build_object('couponCode', v_coupon_code)
  );
  insert into public.audit_events (user_id, event_type, metadata)
  values (v_user_id, 'checkout.started', jsonb_build_object('orderId', v_order_id, 'productId', v_product.id));

  return jsonb_build_object(
    'orderId', v_order_id, 'externalReference', v_order_id::text,
    'productId', v_product.id, 'productName', v_product.name,
    'productDescription', left(v_product.description, 220),
    'subtotalCents', v_subtotal, 'discountCents', v_discount,
    'amountCents', v_subtotal - v_discount, 'currency', v_product.currency,
    'payerEmail', v_email
  );
end;
$$;

create or replace function public.paxinbot_attach_checkout_preference(p_order_id uuid, p_preference_id text)
returns void language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then raise exception 'not_authenticated'; end if;
  if p_preference_id is null or char_length(p_preference_id) not between 8 and 160 then raise exception 'invalid_preference'; end if;
  update public.orders set provider_preference_id = p_preference_id, payment_reference = p_preference_id, updated_at = now()
  where id = p_order_id and user_id = auth.uid() and status = 'pending';
  if not found then raise exception 'order_not_found'; end if;
end;
$$;

create or replace function public.paxinbot_cancel_checkout(p_order_id uuid, p_reason text default 'provider_error')
returns void language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then raise exception 'not_authenticated'; end if;
  update public.orders set status = 'cancelled', provider_status = left(coalesce(p_reason, 'provider_error'), 80), updated_at = now()
  where id = p_order_id and user_id = auth.uid() and status = 'pending';
end;
$$;

create or replace function public.paxinbot_get_checkout_status(p_order_id uuid)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v_result jsonb;
begin
  if auth.uid() is null then raise exception 'not_authenticated'; end if;
  select jsonb_build_object(
    'orderId', o.id, 'status', o.status, 'providerStatus', o.provider_status,
    'amountCents', o.amount_cents, 'currency', o.currency,
    'productName', coalesce(p.name, 'Paxinbot'), 'createdAt', o.created_at, 'paidAt', o.paid_at
  ) into v_result
  from public.orders o left join public.products p on p.id = o.product_id
  where o.id = p_order_id and o.user_id = auth.uid();
  if v_result is null then raise exception 'order_not_found'; end if;
  return v_result;
end;
$$;

create or replace function public.paxinbot_finalize_mercadopago_payment(
  p_payment_id text,
  p_external_reference text,
  p_status text,
  p_amount_cents integer,
  p_currency text,
  p_provider_payload jsonb default '{}'::jsonb
)
returns jsonb language plpgsql security definer set search_path = public as $$
declare
  v_order public.orders%rowtype;
  v_product public.products%rowtype;
  v_entitlement_id uuid;
  v_base timestamptz;
  v_expires timestamptz;
  v_email text;
  v_first_approval boolean := false;
  v_final_status text := lower(coalesce(p_status, ''));
begin
  if auth.role() <> 'service_role' then raise exception 'service_role_required'; end if;
  if p_payment_id is null or char_length(p_payment_id) not between 1 and 120 then raise exception 'invalid_payment'; end if;
  if p_external_reference !~ '^[0-9a-fA-F-]{36}$' then return jsonb_build_object('processed', false, 'reason', 'invalid_reference'); end if;

  select * into v_order from public.orders where external_reference = p_external_reference for update;
  if not found then return jsonb_build_object('processed', false, 'reason', 'order_not_found'); end if;
  -- Serializa concessões do mesmo cliente para que dois pagamentos simultâneos
  -- não calculem a mesma data-base de expiração.
  perform pg_advisory_xact_lock(hashtextextended(v_order.user_id::text, 0));
  select * into v_product from public.products where id = v_order.product_id;
  select email into v_email from auth.users where id = v_order.user_id;

  if v_final_status = 'approved' then
    if p_amount_cents <> v_order.amount_cents or upper(coalesce(p_currency, '')) <> upper(v_order.currency) then
      update public.orders set provider_payment_id = p_payment_id, provider_status = 'amount_mismatch',
        metadata = metadata || jsonb_build_object('paymentSnapshot', p_provider_payload), updated_at = now()
      where id = v_order.id;
      insert into public.audit_events (user_id, event_type, metadata)
      values (v_order.user_id, 'payment.amount_mismatch', jsonb_build_object('orderId', v_order.id, 'paymentId', p_payment_id));
      return jsonb_build_object('processed', false, 'reason', 'amount_mismatch');
    end if;
    if v_order.status = 'paid' and v_order.provider_payment_id = p_payment_id then
      return jsonb_build_object('processed', false, 'reason', 'already_paid', 'orderId', v_order.id);
    end if;
    if exists (select 1 from public.orders o where o.provider_payment_id = p_payment_id and o.id <> v_order.id) then
      return jsonb_build_object('processed', false, 'reason', 'payment_already_used');
    end if;

    v_entitlement_id := v_order.entitlement_id;
    if v_entitlement_id is null then
      if v_product.access_kind = 'lifetime' then
        insert into public.entitlements (user_id, kind, expires_at, source)
        values (v_order.user_id, 'lifetime', null, left('mercado-pago:' || v_order.id::text, 50))
        returning id into v_entitlement_id;
      else
        select greatest(now(), coalesce(max(e.expires_at), now())) into v_base
        from public.entitlements e
        where e.user_id = v_order.user_id and e.kind = 'duration' and e.status = 'active' and e.expires_at > now();
        v_expires := v_base + make_interval(mins => v_product.duration_minutes);
        insert into public.entitlements (user_id, kind, expires_at, source)
        values (v_order.user_id, 'duration', v_expires, left('mercado-pago:' || v_order.id::text, 50))
        returning id into v_entitlement_id;
      end if;
      v_first_approval := true;
    end if;
    update public.orders set status = 'paid', provider_payment_id = p_payment_id,
      provider_status = v_final_status, entitlement_id = v_entitlement_id,
      paid_at = coalesce(paid_at, now()), updated_at = now(),
      metadata = metadata || jsonb_build_object('paymentSnapshot', p_provider_payload)
    where id = v_order.id;
    if v_first_approval and v_order.coupon_id is not null then
      update public.coupons set redemptions = redemptions + 1, updated_at = now() where id = v_order.coupon_id;
    end if;
    if v_first_approval then
      insert into public.audit_events (user_id, event_type, metadata)
      values (v_order.user_id, 'payment.approved', jsonb_build_object('orderId', v_order.id, 'productId', v_order.product_id));
    end if;
  elsif v_final_status in ('refunded', 'charged_back') then
    update public.orders set status = case when v_final_status = 'charged_back' then 'chargeback' else 'refunded' end,
      provider_payment_id = p_payment_id, provider_status = v_final_status, updated_at = now(),
      metadata = metadata || jsonb_build_object('paymentSnapshot', p_provider_payload)
    where id = v_order.id;
    if v_order.entitlement_id is not null then
      update public.entitlements set status = 'revoked', revoked_at = coalesce(revoked_at, now()) where id = v_order.entitlement_id;
      update public.desktop_sessions set revoked_at = now() where user_id = v_order.user_id and revoked_at is null;
    end if;
    insert into public.audit_events (user_id, event_type, metadata)
    values (v_order.user_id, 'payment.' || v_final_status, jsonb_build_object('orderId', v_order.id));
  elsif v_final_status in ('rejected', 'cancelled') and v_order.status <> 'paid' then
    update public.orders set status = 'cancelled', provider_payment_id = p_payment_id,
      provider_status = v_final_status, updated_at = now(),
      metadata = metadata || jsonb_build_object('paymentSnapshot', p_provider_payload)
    where id = v_order.id;
  else
    update public.orders set provider_payment_id = p_payment_id, provider_status = v_final_status,
      updated_at = now(), metadata = metadata || jsonb_build_object('paymentSnapshot', p_provider_payload)
    where id = v_order.id and status = 'pending';
  end if;

  return jsonb_build_object(
    'processed', v_first_approval, 'orderId', v_order.id, 'status',
    case when v_final_status = 'approved' then 'paid' else v_final_status end,
    'email', v_email, 'productName', v_product.name, 'expiresAt', v_expires,
    'amountCents', v_order.amount_cents, 'currency', v_order.currency
  );
end;
$$;

create or replace function public.paxinbot_list_my_orders()
returns jsonb language plpgsql stable security definer set search_path = public as $$
begin
  if auth.uid() is null then raise exception 'not_authenticated'; end if;
  return coalesce((select jsonb_agg(row_to_json(x)) from (
    select o.id, o.subtotal_cents as "subtotalCents", o.discount_cents as "discountCents",
      o.amount_cents as "amountCents", o.currency, o.status, o.provider_status as "providerStatus",
      o.created_at as "createdAt", o.paid_at as "paidAt", p.name as "productName"
    from public.orders o left join public.products p on p.id = o.product_id
    where o.user_id = auth.uid() order by o.created_at desc limit 100
  ) x), '[]'::jsonb);
end;
$$;

create or replace function public.paxinbot_owner_approve_order(p_order_id uuid)
returns jsonb language plpgsql security definer set search_path = public, auth, pg_temp as $$
declare
  v_order public.orders%rowtype;
  v_product public.products%rowtype;
  v_entitlement_id uuid;
  v_base timestamptz;
  v_expires timestamptz;
begin
  perform public.paxinbot_require_owner();
  select * into v_order from public.orders where id = p_order_id for update;
  if not found then raise exception 'order_not_found'; end if;
  if v_order.status = 'paid' then raise exception 'order_already_paid'; end if;

  select * into v_product from public.products where id = v_order.product_id;

  v_entitlement_id := v_order.entitlement_id;
  if v_entitlement_id is null and v_product.id is not null then
    if v_product.access_kind = 'lifetime' then
      insert into public.entitlements (user_id, kind, expires_at, source)
      values (v_order.user_id, 'lifetime', null, 'owner-approve:' || v_order.id::text)
      returning id into v_entitlement_id;
    else
      select greatest(now(), coalesce(max(e.expires_at), now())) into v_base
      from public.entitlements e
      where e.user_id = v_order.user_id and e.kind = 'duration' and e.status = 'active' and e.expires_at > now();
      v_expires := coalesce(v_base, now()) + make_interval(mins => coalesce(v_product.duration_minutes, 60));
      insert into public.entitlements (user_id, kind, expires_at, source)
      values (v_order.user_id, 'duration', v_expires, 'owner-approve:' || v_order.id::text)
      returning id into v_entitlement_id;
    end if;
  end if;

  update public.orders
  set status = 'paid',
      paid_at = coalesce(paid_at, now()),
      provider_status = 'manual_approved',
      entitlement_id = coalesce(entitlement_id, v_entitlement_id),
      updated_at = now()
  where id = v_order.id;

  insert into public.audit_events (user_id, event_type, metadata)
  values (auth.uid(), 'owner.order_approved', jsonb_build_object('orderId', p_order_id, 'targetUserId', v_order.user_id));

  return jsonb_build_object('ok', true);
end;
$$;

create or replace function public.paxinbot_owner_refund_order(p_order_id uuid)
returns jsonb language plpgsql security definer set search_path = public, auth, pg_temp as $$
declare
  v_order public.orders%rowtype;
begin
  perform public.paxinbot_require_owner();
  select * into v_order from public.orders where id = p_order_id for update;
  if not found then raise exception 'order_not_found'; end if;
  if v_order.status = 'refunded' then raise exception 'order_already_refunded'; end if;

  if v_order.entitlement_id is not null then
    update public.entitlements
    set status = 'revoked', revoked_at = now()
    where id = v_order.entitlement_id and status = 'active';
  end if;

  update public.entitlements
  set status = 'revoked', revoked_at = now()
  where user_id = v_order.user_id and source like '%' || v_order.id::text || '%' and status = 'active';

  update public.desktop_sessions
  set revoked_at = now()
  where user_id = v_order.user_id and revoked_at is null;

  update public.orders
  set status = 'refunded',
      provider_status = 'manual_refunded',
      updated_at = now()
  where id = v_order.id;

  insert into public.audit_events (user_id, event_type, metadata)
  values (auth.uid(), 'owner.order_refunded', jsonb_build_object('orderId', p_order_id, 'targetUserId', v_order.user_id));

  return jsonb_build_object('ok', true);
end;
$$;

create or replace function public.paxinbot_owner_list_orders(p_query text default '')
returns jsonb language plpgsql stable security definer set search_path = public, auth, pg_temp as $$
declare
  v_query text := lower(trim(coalesce(p_query, '')));
begin
  perform public.paxinbot_require_owner();
  return coalesce((select jsonb_agg(row_to_json(x) order by x."createdAt" desc) from (
    select o.id, u.email, coalesce(p.name, 'Produto Paxinbot') as "productName", o.subtotal_cents as "subtotalCents",
      o.discount_cents as "discountCents", o.amount_cents as "amountCents", o.currency,
      case
        when o.status = 'pending' and o.created_at < now() - interval '24 hours' then 'expired'
        else o.status
      end as status,
      o.payment_provider as "paymentProvider", coalesce(o.provider_status, '') as "providerStatus",
      o.created_at as "createdAt", o.paid_at as "paidAt"
    from public.orders o join auth.users u on u.id = o.user_id
    left join public.products p on p.id = o.product_id
    where v_query = ''
      or lower(u.email) like '%' || v_query || '%'
      or lower(o.id::text) like '%' || v_query || '%'
      or lower(coalesce(p.name, '')) like '%' || v_query || '%'
      or lower(o.status) like '%' || v_query || '%'
    order by o.created_at desc limit 200
  ) x), '[]'::jsonb);
end;
$$;

revoke all on function public.paxinbot_prepare_checkout(uuid,text) from public;
revoke all on function public.paxinbot_attach_checkout_preference(uuid,text) from public;
revoke all on function public.paxinbot_cancel_checkout(uuid,text) from public;
revoke all on function public.paxinbot_get_checkout_status(uuid) from public;
revoke all on function public.paxinbot_finalize_mercadopago_payment(text,text,text,integer,text,jsonb) from public;
grant execute on function public.paxinbot_prepare_checkout(uuid,text) to authenticated;
grant execute on function public.paxinbot_attach_checkout_preference(uuid,text) to authenticated;
grant execute on function public.paxinbot_cancel_checkout(uuid,text) to authenticated;
grant execute on function public.paxinbot_get_checkout_status(uuid) to authenticated;
grant execute on function public.paxinbot_finalize_mercadopago_payment(text,text,text,integer,text,jsonb) to service_role;
