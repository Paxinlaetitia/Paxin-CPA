-- Paxinbot checkout v1: cotação, idempotência e PIX interno via Mercado Pago Orders API.
-- Execute depois de 20260823_usage_pause.sql.

alter table public.orders add column if not exists client_request_id uuid;
alter table public.orders add column if not exists provider_order_id text;
alter table public.orders add column if not exists payment_expires_at timestamptz;

create unique index if not exists orders_user_client_request_unique
  on public.orders(user_id, client_request_id) where client_request_id is not null;
create unique index if not exists orders_provider_order_unique
  on public.orders(provider_order_id) where provider_order_id is not null;

create or replace function public.paxinbot_quote_checkout(p_product_id uuid, p_coupon_code text default null)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare
  v_product public.products%rowtype;
  v_coupon public.coupons%rowtype;
  v_coupon_code text := nullif(upper(trim(coalesce(p_coupon_code, ''))), '');
  v_subtotal integer;
  v_discount integer := 0;
begin
  if auth.uid() is null then raise exception 'not_authenticated'; end if;
  if p_product_id is null then raise exception 'invalid_product'; end if;
  if v_coupon_code is not null and v_coupon_code !~ '^[A-Z0-9_-]{3,32}$' then raise exception 'invalid_coupon'; end if;

  select * into v_product from public.products where id=p_product_id and active is true;
  if not found then raise exception 'product_unavailable'; end if;
  if v_product.price_cents <= 0 or v_product.currency <> 'BRL' then raise exception 'product_not_payable'; end if;
  if exists (select 1 from public.entitlements e where e.user_id=auth.uid() and e.kind='lifetime' and e.status='active' and e.starts_at<=now()) then
    raise exception 'lifetime_already_active';
  end if;

  v_subtotal := v_product.price_cents;
  if v_coupon_code is not null then
    select * into v_coupon from public.coupons c where c.code=v_coupon_code;
    if not found or not v_coupon.active
       or (v_coupon.starts_at is not null and v_coupon.starts_at>now())
       or (v_coupon.expires_at is not null and v_coupon.expires_at<=now())
       or (v_coupon.max_redemptions is not null and
           v_coupon.redemptions+(select count(*) from public.orders o where o.coupon_id=v_coupon.id and o.status='pending')>=v_coupon.max_redemptions) then
      raise exception 'coupon_unavailable';
    end if;
    if v_coupon.discount_type='percent' then
      v_discount := least(v_subtotal, round(v_subtotal*least(v_coupon.discount_value,100)::numeric/100)::integer);
    else
      v_discount := least(v_subtotal,v_coupon.discount_value);
    end if;
  end if;
  if v_subtotal-v_discount<=0 then raise exception 'zero_value_checkout'; end if;

  return jsonb_build_object(
    'productId',v_product.id,'productName',v_product.name,'productDescription',left(v_product.description,220),
    'accessKind',v_product.access_kind,'durationMinutes',v_product.duration_minutes,
    'subtotalCents',v_subtotal,'discountCents',v_discount,'amountCents',v_subtotal-v_discount,
    'currency',v_product.currency,'couponCode',v_coupon_code
  );
end;
$$;

create or replace function public.paxinbot_prepare_checkout_v2(
  p_product_id uuid,
  p_coupon_code text,
  p_client_request_id uuid,
  p_payment_method text,
  p_payer_name text
)
returns jsonb language plpgsql security definer set search_path = public as $$
declare
  v_existing public.orders%rowtype;
  v_product public.products%rowtype;
  v_result jsonb;
  v_email text;
  v_name text := trim(coalesce(p_payer_name,''));
begin
  if auth.uid() is null then raise exception 'not_authenticated'; end if;
  if p_client_request_id is null then raise exception 'invalid_client_request'; end if;
  if p_payment_method not in ('pix','checkout_pro') then raise exception 'invalid_payment_method'; end if;
  if char_length(v_name) not between 2 and 100 then raise exception 'invalid_payer_name'; end if;

  perform pg_advisory_xact_lock(hashtextextended(auth.uid()::text || ':' || p_client_request_id::text,0));
  select * into v_existing from public.orders
    where user_id=auth.uid() and client_request_id=p_client_request_id;
  if found then
    select * into v_product from public.products where id=v_existing.product_id;
    select email into v_email from auth.users where id=auth.uid();
    return jsonb_build_object(
      'orderId',v_existing.id,'externalReference',v_existing.external_reference,
      'productId',v_product.id,'productName',v_product.name,'productDescription',left(v_product.description,220),
      'subtotalCents',v_existing.subtotal_cents,'discountCents',v_existing.discount_cents,
      'amountCents',v_existing.amount_cents,'currency',v_existing.currency,'payerEmail',v_email,
      'paymentMethod',coalesce(v_existing.metadata->>'paymentMethod',p_payment_method),'reused',true
    );
  end if;

  v_result := public.paxinbot_prepare_checkout(p_product_id,p_coupon_code);
  update public.orders set client_request_id=p_client_request_id,
    metadata=metadata || jsonb_build_object('paymentMethod',p_payment_method,'payerName',v_name),updated_at=now()
    where id=(v_result->>'orderId')::uuid and user_id=auth.uid();
  return v_result || jsonb_build_object('paymentMethod',p_payment_method,'reused',false);
end;
$$;

create or replace function public.paxinbot_attach_pix_order(
  p_order_id uuid,
  p_provider_order_id text,
  p_provider_payment_id text,
  p_expires_at timestamptz
)
returns void language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then raise exception 'not_authenticated'; end if;
  if char_length(coalesce(p_provider_order_id,'')) not between 8 and 160 then raise exception 'invalid_provider_order'; end if;
  if char_length(coalesce(p_provider_payment_id,'')) not between 1 and 160 then raise exception 'invalid_provider_payment'; end if;
  if p_expires_at is null or p_expires_at<=now() or p_expires_at>now()+interval '31 days' then raise exception 'invalid_payment_expiration'; end if;
  update public.orders set provider_order_id=p_provider_order_id,provider_payment_id=p_provider_payment_id,
    payment_reference=p_provider_order_id,payment_expires_at=p_expires_at,provider_status='action_required',updated_at=now()
    where id=p_order_id and user_id=auth.uid() and status='pending';
  if not found then raise exception 'order_not_found'; end if;
end;
$$;

create or replace function public.paxinbot_get_checkout_status(p_order_id uuid)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v_result jsonb;
begin
  if auth.uid() is null then raise exception 'not_authenticated'; end if;
  select jsonb_build_object(
    'orderId',o.id,'status',o.status,'providerStatus',o.provider_status,
    'amountCents',o.amount_cents,'currency',o.currency,
    'productName',coalesce(p.name,'Paxinbot'),'createdAt',o.created_at,'paidAt',o.paid_at,
    'paymentMethod',coalesce(o.metadata->>'paymentMethod','checkout_pro'),'paymentExpiresAt',o.payment_expires_at
  ) into v_result
  from public.orders o left join public.products p on p.id=o.product_id
  where o.id=p_order_id and o.user_id=auth.uid();
  if v_result is null then raise exception 'order_not_found'; end if;
  return v_result;
end;
$$;

create or replace function public.paxinbot_get_my_order(p_order_id uuid)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v_result jsonb;
begin
  if auth.uid() is null then raise exception 'not_authenticated'; end if;
  select jsonb_build_object(
    'id',o.id,'status',o.status,'providerStatus',o.provider_status,
    'subtotalCents',o.subtotal_cents,'discountCents',o.discount_cents,
    'amountCents',o.amount_cents,'currency',o.currency,'createdAt',o.created_at,'paidAt',o.paid_at,
    'paymentMethod',coalesce(o.metadata->>'paymentMethod','checkout_pro'),'paymentExpiresAt',o.payment_expires_at,
    'product',jsonb_build_object('name',coalesce(p.name,'Paxinbot'),'description',coalesce(p.description,''),'accessKind',p.access_kind,'durationMinutes',p.duration_minutes)
  ) into v_result from public.orders o left join public.products p on p.id=o.product_id
  where o.id=p_order_id and o.user_id=auth.uid();
  if v_result is null then raise exception 'order_not_found'; end if;
  return v_result;
end;
$$;

revoke all on function public.paxinbot_quote_checkout(uuid,text) from public;
revoke all on function public.paxinbot_prepare_checkout_v2(uuid,text,uuid,text,text) from public;
revoke all on function public.paxinbot_attach_pix_order(uuid,text,text,timestamptz) from public;
revoke all on function public.paxinbot_get_my_order(uuid) from public;
grant execute on function public.paxinbot_quote_checkout(uuid,text) to authenticated;
grant execute on function public.paxinbot_prepare_checkout_v2(uuid,text,uuid,text,text) to authenticated;
grant execute on function public.paxinbot_attach_pix_order(uuid,text,text,timestamptz) to authenticated;
grant execute on function public.paxinbot_get_my_order(uuid) to authenticated;
