-- A conta owner é a proprietária do produto e possui acesso vitalício ao app.
-- Clientes continuam dependendo exclusivamente de uma entitlement válida.
create or replace function public.paxinbot_active_entitlement(p_user_id uuid)
returns table(kind text, expires_at timestamptz, source text)
language sql
stable
security definer
set search_path = public
as $$
  with eligible as (
    select 'lifetime'::text as kind, null::timestamptz as expires_at, 'owner'::text as source, 0 as priority
    from public.profiles p
    where p.id = p_user_id and p.role = 'owner' and p.disabled_at is null
    union all
    select e.kind, e.expires_at, e.source, case e.kind when 'lifetime' then 1 else 2 end as priority
    from public.entitlements e
    join public.profiles p on p.id = e.user_id
    where e.user_id = p_user_id
      and p.disabled_at is null
      and e.status = 'active'
      and e.starts_at <= now()
      and (e.expires_at is null or e.expires_at > now())
  )
  select eligible.kind, eligible.expires_at, eligible.source
  from eligible
  order by eligible.priority, eligible.expires_at desc nulls first
  limit 1;
$$;

revoke all on function public.paxinbot_active_entitlement(uuid) from public, anon, authenticated;

