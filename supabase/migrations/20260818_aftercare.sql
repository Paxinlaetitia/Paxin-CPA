-- Paxinbot: pós-venda, preferências, atividade e suporte.
-- Execute depois de 20260817_checkout.sql.

alter table public.profiles add column if not exists notify_product_updates boolean not null default false;
alter table public.profiles add column if not exists notify_support_updates boolean not null default true;

create table if not exists public.support_tickets (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  category text not null check (category in ('technical','payment','access','other')),
  subject text not null check (char_length(subject) between 5 and 120),
  status text not null default 'open' check (status in ('open','in_progress','resolved','closed')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  resolved_at timestamptz
);

create table if not exists public.support_messages (
  id uuid primary key default gen_random_uuid(),
  ticket_id uuid not null references public.support_tickets(id) on delete cascade,
  author_id uuid references auth.users(id) on delete set null,
  author_kind text not null check (author_kind in ('customer','owner')),
  body text not null check (char_length(body) between 2 and 3000),
  created_at timestamptz not null default now()
);

create index if not exists support_tickets_user_updated_idx on public.support_tickets (user_id, updated_at desc);
create index if not exists support_tickets_status_updated_idx on public.support_tickets (status, updated_at desc);
create index if not exists support_messages_ticket_created_idx on public.support_messages (ticket_id, created_at);
alter table public.support_tickets enable row level security;
alter table public.support_messages enable row level security;

create or replace function public.paxinbot_get_my_preferences()
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v_result jsonb;
begin
  if auth.uid() is null then raise exception 'not_authenticated'; end if;
  select jsonb_build_object(
    'productUpdates', p.notify_product_updates,
    'supportUpdates', p.notify_support_updates,
    'securityAlerts', true,
    'paymentReceipts', true
  ) into v_result from public.profiles p where p.id = auth.uid();
  return coalesce(v_result, jsonb_build_object('productUpdates',false,'supportUpdates',true,'securityAlerts',true,'paymentReceipts',true));
end;
$$;

create or replace function public.paxinbot_update_my_preferences(p_product_updates boolean, p_support_updates boolean)
returns jsonb language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then raise exception 'not_authenticated'; end if;
  update public.profiles set
    notify_product_updates = coalesce(p_product_updates, false),
    notify_support_updates = coalesce(p_support_updates, true)
  where id = auth.uid();
  insert into public.audit_events (user_id, event_type, metadata)
  values (auth.uid(), 'account.preferences_updated', jsonb_build_object('productUpdates',coalesce(p_product_updates,false),'supportUpdates',coalesce(p_support_updates,true)));
  return public.paxinbot_get_my_preferences();
end;
$$;

create or replace function public.paxinbot_list_my_activity()
returns jsonb language plpgsql stable security definer set search_path = public as $$
begin
  if auth.uid() is null then raise exception 'not_authenticated'; end if;
  return coalesce((select jsonb_agg(row_to_json(x)) from (
    select a.id, a.event_type as "eventType", a.created_at as "createdAt"
    from public.audit_events a where a.user_id = auth.uid()
    order by a.created_at desc limit 50
  ) x), '[]'::jsonb);
end;
$$;

create or replace function public.paxinbot_get_my_order(p_order_id uuid)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v_result jsonb;
begin
  if auth.uid() is null then raise exception 'not_authenticated'; end if;
  select jsonb_build_object(
    'id', o.id, 'status', o.status, 'providerStatus', o.provider_status,
    'subtotalCents', o.subtotal_cents, 'discountCents', o.discount_cents,
    'amountCents', o.amount_cents, 'currency', o.currency,
    'createdAt', o.created_at, 'paidAt', o.paid_at,
    'product', jsonb_build_object('name',coalesce(p.name,'Paxinbot'),'description',coalesce(p.description,''),'accessKind',p.access_kind,'durationMinutes',p.duration_minutes)
  ) into v_result from public.orders o left join public.products p on p.id = o.product_id
  where o.id = p_order_id and o.user_id = auth.uid();
  if v_result is null then raise exception 'order_not_found'; end if;
  return v_result;
end;
$$;

create or replace function public.paxinbot_resume_checkout(p_order_id uuid)
returns jsonb language plpgsql security definer set search_path = public as $$
declare v_order public.orders%rowtype; v_product public.products%rowtype; v_email text;
begin
  if auth.uid() is null then raise exception 'not_authenticated'; end if;
  select * into v_order from public.orders where id = p_order_id and user_id = auth.uid() for update;
  if not found then raise exception 'order_not_found'; end if;
  if v_order.status <> 'pending' then raise exception 'order_not_pending'; end if;
  if v_order.created_at < now() - interval '7 days' then
    update public.orders set status = 'cancelled', provider_status = 'expired', updated_at = now() where id = v_order.id;
    raise exception 'order_expired';
  end if;
  select * into v_product from public.products where id = v_order.product_id and active is true;
  if not found then raise exception 'product_unavailable'; end if;
  select email into v_email from auth.users where id = auth.uid();
  insert into public.audit_events (user_id, event_type, metadata)
  values (auth.uid(), 'checkout.resumed', jsonb_build_object('orderId',v_order.id));
  return jsonb_build_object(
    'orderId',v_order.id,'externalReference',v_order.external_reference,
    'productId',v_product.id,'productName',v_product.name,
    'productDescription',left(v_product.description,220),
    'subtotalCents',v_order.subtotal_cents,'discountCents',v_order.discount_cents,
    'amountCents',v_order.amount_cents,'currency',v_order.currency,'payerEmail',v_email
  );
end;
$$;

create or replace function public.paxinbot_get_my_receipt(p_order_id uuid)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v_result jsonb;
begin
  if auth.uid() is null then raise exception 'not_authenticated'; end if;
  select jsonb_build_object(
    'orderId',o.id,'email',u.email,'productName',coalesce(p.name,'Paxinbot'),
    'amountCents',o.amount_cents,'discountCents',o.discount_cents,
    'currency',o.currency,'paidAt',o.paid_at
  ) into v_result from public.orders o join auth.users u on u.id = o.user_id
  left join public.products p on p.id = o.product_id
  where o.id = p_order_id and o.user_id = auth.uid() and o.status = 'paid';
  if v_result is null then raise exception 'receipt_unavailable'; end if;
  return v_result;
end;
$$;

create or replace function public.paxinbot_create_support_ticket(p_category text, p_subject text, p_message text)
returns jsonb language plpgsql security definer set search_path = public as $$
declare v_ticket_id uuid;
begin
  if auth.uid() is null then raise exception 'not_authenticated'; end if;
  if p_category not in ('technical','payment','access','other')
     or char_length(trim(coalesce(p_subject,''))) not between 5 and 120
     or char_length(trim(coalesce(p_message,''))) not between 10 and 3000 then raise exception 'invalid_ticket'; end if;
  if (select count(*) from public.support_tickets where user_id = auth.uid() and created_at > now() - interval '24 hours') >= 5 then
    raise exception 'ticket_rate_limited';
  end if;
  insert into public.support_tickets (user_id,category,subject)
  values (auth.uid(),p_category,trim(p_subject)) returning id into v_ticket_id;
  insert into public.support_messages (ticket_id,author_id,author_kind,body)
  values (v_ticket_id,auth.uid(),'customer',trim(p_message));
  insert into public.audit_events (user_id,event_type,metadata)
  values (auth.uid(),'support.ticket_created',jsonb_build_object('ticketId',v_ticket_id,'category',p_category));
  return jsonb_build_object('id',v_ticket_id);
end;
$$;

create or replace function public.paxinbot_reply_support_ticket(p_ticket_id uuid, p_message text)
returns void language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then raise exception 'not_authenticated'; end if;
  if char_length(trim(coalesce(p_message,''))) not between 2 and 3000 then raise exception 'invalid_message'; end if;
  if not exists (select 1 from public.support_tickets where id = p_ticket_id and user_id = auth.uid() and status <> 'closed') then raise exception 'ticket_unavailable'; end if;
  insert into public.support_messages (ticket_id,author_id,author_kind,body)
  values (p_ticket_id,auth.uid(),'customer',trim(p_message));
  update public.support_tickets set status = case when status = 'resolved' then 'open' else status end, updated_at = now(), resolved_at = null where id = p_ticket_id;
end;
$$;

create or replace function public.paxinbot_list_my_support_tickets()
returns jsonb language plpgsql stable security definer set search_path = public as $$
begin
  if auth.uid() is null then raise exception 'not_authenticated'; end if;
  return coalesce((select jsonb_agg(jsonb_build_object(
    'id',t.id,'category',t.category,'subject',t.subject,'status',t.status,
    'createdAt',t.created_at,'updatedAt',t.updated_at,
    'messages',coalesce((select jsonb_agg(jsonb_build_object('id',m.id,'authorKind',m.author_kind,'body',m.body,'createdAt',m.created_at) order by m.created_at) from public.support_messages m where m.ticket_id = t.id),'[]'::jsonb)
  ) order by t.updated_at desc) from (select * from public.support_tickets where user_id = auth.uid() order by updated_at desc limit 20) t), '[]'::jsonb);
end;
$$;

create or replace function public.paxinbot_owner_list_support_tickets()
returns jsonb language plpgsql stable security definer set search_path = public as $$
begin
  perform public.paxinbot_require_owner();
  return coalesce((select jsonb_agg(jsonb_build_object(
    'id',t.id,'email',u.email,'category',t.category,'subject',t.subject,'status',t.status,
    'createdAt',t.created_at,'updatedAt',t.updated_at,
    'messages',coalesce((select jsonb_agg(jsonb_build_object('id',m.id,'authorKind',m.author_kind,'body',m.body,'createdAt',m.created_at) order by m.created_at) from public.support_messages m where m.ticket_id = t.id),'[]'::jsonb)
  ) order by t.updated_at desc) from (select * from public.support_tickets order by updated_at desc limit 100) t join auth.users u on u.id = t.user_id), '[]'::jsonb);
end;
$$;

create or replace function public.paxinbot_owner_reply_support_ticket(p_ticket_id uuid, p_message text)
returns jsonb language plpgsql security definer set search_path = public as $$
declare v_email text; v_subject text; v_notify boolean;
begin
  perform public.paxinbot_require_owner();
  if char_length(trim(coalesce(p_message,''))) not between 2 and 3000 then raise exception 'invalid_message'; end if;
  select u.email,t.subject,p.notify_support_updates into v_email,v_subject,v_notify
  from public.support_tickets t join auth.users u on u.id=t.user_id join public.profiles p on p.id=t.user_id
  where t.id=p_ticket_id and t.status <> 'closed' for update of t;
  if v_email is null then raise exception 'ticket_unavailable'; end if;
  insert into public.support_messages (ticket_id,author_id,author_kind,body)
  values (p_ticket_id,auth.uid(),'owner',trim(p_message));
  update public.support_tickets set status='in_progress',updated_at=now(),resolved_at=null where id=p_ticket_id;
  insert into public.audit_events (user_id,event_type,metadata)
  values (auth.uid(),'owner.support_replied',jsonb_build_object('ticketId',p_ticket_id));
  return jsonb_build_object('email',v_email,'subject',v_subject,'notify',v_notify,'ticketId',p_ticket_id);
end;
$$;

create or replace function public.paxinbot_owner_update_support_status(p_ticket_id uuid, p_status text)
returns void language plpgsql security definer set search_path = public as $$
begin
  perform public.paxinbot_require_owner();
  if p_status not in ('open','in_progress','resolved','closed') then raise exception 'invalid_ticket_status'; end if;
  update public.support_tickets set status=p_status,updated_at=now(),resolved_at=case when p_status in ('resolved','closed') then now() else null end where id=p_ticket_id;
  if not found then raise exception 'ticket_unavailable'; end if;
  insert into public.audit_events (user_id,event_type,metadata)
  values (auth.uid(),'owner.support_status_changed',jsonb_build_object('ticketId',p_ticket_id,'status',p_status));
end;
$$;

create or replace function public.paxinbot_owner_overview()
returns jsonb language plpgsql security definer set search_path = public as $$
begin
  perform public.paxinbot_require_owner();
  return jsonb_build_object(
    'customers',(select count(*) from public.profiles where role='customer' and disabled_at is null),
    'activeAccesses',(select count(*) from public.entitlements where status='active' and starts_at<=now() and (expires_at is null or expires_at>now())),
    'activeProducts',(select count(*) from public.products where active),
    'activeCoupons',(select count(*) from public.coupons where active and (expires_at is null or expires_at>now())),
    'paidOrders',(select count(*) from public.orders where status='paid'),
    'pendingOrders',(select count(*) from public.orders where status='pending'),
    'revenueCents',(select coalesce(sum(amount_cents),0) from public.orders where status='paid'),
    'openTickets',(select count(*) from public.support_tickets where status in ('open','in_progress')),
    'lastPaymentEventAt',(select max(created_at) from public.audit_events where event_type like 'payment.%')
  );
end;
$$;

revoke all on function public.paxinbot_get_my_preferences() from public;
revoke all on function public.paxinbot_update_my_preferences(boolean,boolean) from public;
revoke all on function public.paxinbot_list_my_activity() from public;
revoke all on function public.paxinbot_get_my_order(uuid) from public;
revoke all on function public.paxinbot_resume_checkout(uuid) from public;
revoke all on function public.paxinbot_get_my_receipt(uuid) from public;
revoke all on function public.paxinbot_create_support_ticket(text,text,text) from public;
revoke all on function public.paxinbot_reply_support_ticket(uuid,text) from public;
revoke all on function public.paxinbot_list_my_support_tickets() from public;
revoke all on function public.paxinbot_owner_list_support_tickets() from public;
revoke all on function public.paxinbot_owner_reply_support_ticket(uuid,text) from public;
revoke all on function public.paxinbot_owner_update_support_status(uuid,text) from public;

grant execute on function public.paxinbot_get_my_preferences() to authenticated;
grant execute on function public.paxinbot_update_my_preferences(boolean,boolean) to authenticated;
grant execute on function public.paxinbot_list_my_activity() to authenticated;
grant execute on function public.paxinbot_get_my_order(uuid) to authenticated;
grant execute on function public.paxinbot_resume_checkout(uuid) to authenticated;
grant execute on function public.paxinbot_get_my_receipt(uuid) to authenticated;
grant execute on function public.paxinbot_create_support_ticket(text,text,text) to authenticated;
grant execute on function public.paxinbot_reply_support_ticket(uuid,text) to authenticated;
grant execute on function public.paxinbot_list_my_support_tickets() to authenticated;
grant execute on function public.paxinbot_owner_list_support_tickets() to authenticated;
grant execute on function public.paxinbot_owner_reply_support_ticket(uuid,text) to authenticated;
grant execute on function public.paxinbot_owner_update_support_status(uuid,text) to authenticated;
