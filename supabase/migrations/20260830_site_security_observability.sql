-- Paxinbot: observabilidade defensiva do site sem dados pessoais brutos.
-- Execute depois de 20260829_api_abuse_limits.sql.

create table if not exists public.site_security_events (
  id uuid primary key default extensions.gen_random_uuid(),
  event_id uuid not null unique,
  request_id uuid not null,
  occurred_at timestamptz not null default now(),
  event_type text not null check (event_type in (
    'edge.host_rejected','csrf.rejected','rate_limit.blocked',
    'auth.login_rejected','auth.code_rejected','auth.session_rejected',
    'auth.password_changed','checkout.provider_failure',
    'webhook.signature_rejected','webhook.provider_failure',
    'webhook.payment_processed','admin.access_denied'
  )),
  severity smallint not null check (severity between 0 and 100),
  route text not null check (route ~ '^/api/[A-Za-z0-9_./-]{1,115}$'),
  actor_user_id uuid references auth.users(id) on delete set null,
  subject_hash text check (subject_hash is null or subject_hash ~ '^[a-f0-9]{64}$'),
  edge_trace_hash text check (edge_trace_hash is null or edge_trace_hash ~ '^[a-f0-9]{64}$'),
  details jsonb not null default '{}'::jsonb check (
    jsonb_typeof(details) = 'object' and octet_length(details::text) <= 768
  )
);

create index if not exists site_security_events_time_idx
  on public.site_security_events(occurred_at desc);
create index if not exists site_security_events_type_idx
  on public.site_security_events(event_type, occurred_at desc);
create index if not exists site_security_events_actor_idx
  on public.site_security_events(actor_user_id, occurred_at desc)
  where actor_user_id is not null;

alter table public.site_security_events enable row level security;
revoke all on table public.site_security_events from public, anon, authenticated;

create or replace function public.paxinbot_record_site_security_event(
  p_event_id uuid,
  p_request_id uuid,
  p_event_type text,
  p_severity smallint,
  p_route text,
  p_actor_user_id uuid default null,
  p_subject_hash text default null,
  p_edge_trace_hash text default null,
  p_details jsonb default '{}'::jsonb
)
returns boolean language plpgsql security definer set search_path=public,auth,pg_temp as $$
declare v_details jsonb := coalesce(p_details, '{}'::jsonb);
begin
  if auth.role() <> 'service_role' then raise exception 'service_role_required'; end if;
  if p_event_id is null or p_request_id is null or p_event_type not in (
    'edge.host_rejected','csrf.rejected','rate_limit.blocked',
    'auth.login_rejected','auth.code_rejected','auth.session_rejected',
    'auth.password_changed','checkout.provider_failure',
    'webhook.signature_rejected','webhook.provider_failure',
    'webhook.payment_processed','admin.access_denied'
  ) or p_severity not between 0 and 100
    or p_route !~ '^/api/[A-Za-z0-9_./-]{1,115}$'
    or (p_actor_user_id is not null and not exists(select 1 from auth.users where id=p_actor_user_id))
    or (p_subject_hash is not null and p_subject_hash !~ '^[a-f0-9]{64}$')
    or (p_edge_trace_hash is not null and p_edge_trace_hash !~ '^[a-f0-9]{64}$')
    or jsonb_typeof(v_details) <> 'object' or octet_length(v_details::text) > 768
    or exists(select 1 from jsonb_object_keys(v_details) key
      where key not in ('reasonCode','outcome','provider','scope','method','status'))
    or exists(select 1 from jsonb_each_text(v_details) entry
      where entry.value !~ '^[A-Za-z0-9_.:-]{1,80}$')
  then raise exception 'site_security_event_invalid'; end if;

  insert into public.site_security_events(
    event_id,request_id,event_type,severity,route,actor_user_id,
    subject_hash,edge_trace_hash,details
  ) values (
    p_event_id,p_request_id,p_event_type,p_severity,p_route,p_actor_user_id,
    p_subject_hash,p_edge_trace_hash,v_details
  ) on conflict(event_id) do nothing;

  -- Limpeza probabilística: aproximadamente 1/16 das inserções remove eventos
  -- antigos, sem exigir cron ou extensão adicional no projeto Supabase.
  if left(p_event_id::text, 1) = '0' then
    delete from public.site_security_events where occurred_at < now() - interval '90 days';
  end if;
  return true;
end;
$$;

create or replace function public.paxinbot_owner_list_site_security_events(p_limit integer default 200)
returns jsonb language plpgsql stable security definer set search_path=public,auth,pg_temp as $$
begin
  perform public.paxinbot_require_owner();
  return coalesce((select jsonb_agg(row_to_json(x) order by x."createdAt" desc) from (
    select e.event_id as id, e.event_type as "eventType", u.email,
      e.occurred_at as "createdAt", e.severity, e.route,
      e.details || jsonb_build_object('requestId',e.request_id) as metadata
    from public.site_security_events e
    left join auth.users u on u.id=e.actor_user_id
    order by e.occurred_at desc
    limit least(greatest(coalesce(p_limit,200),1),500)
  ) x), '[]'::jsonb);
end;
$$;

revoke all on function public.paxinbot_record_site_security_event(uuid,uuid,text,smallint,text,uuid,text,text,jsonb) from public,anon,authenticated;
revoke all on function public.paxinbot_owner_list_site_security_events(integer) from public,anon,authenticated;
grant execute on function public.paxinbot_record_site_security_event(uuid,uuid,text,smallint,text,uuid,text,text,jsonb) to service_role;
grant execute on function public.paxinbot_owner_list_site_security_events(integer) to authenticated;
