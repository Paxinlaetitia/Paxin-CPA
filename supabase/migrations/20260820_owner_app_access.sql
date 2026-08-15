-- A conta owner é a proprietária do produto e recebe uma entitlement vitalícia
-- persistida, igual às demais concessões. Clientes continuam dependendo de uma
-- entitlement comprada ou concedida explicitamente.

insert into public.entitlements (user_id, kind, status, starts_at, expires_at, source)
select p.id, 'lifetime', 'active', now(), null, 'owner'
from public.profiles p
where p.role = 'owner'
  and p.disabled_at is null
  and not exists (
    select 1 from public.entitlements e
    where e.user_id = p.id
      and e.status = 'active'
      and e.starts_at <= now()
      and (e.expires_at is null or e.expires_at > now())
  );

-- Mantém uma única regra de consulta para owner e cliente. Esta definição
-- substitui a versão sintética anterior e evita incompatibilidades de plano.
create or replace function public.paxinbot_active_entitlement(p_user_id uuid)
returns table(kind text, expires_at timestamptz, source text)
language sql
stable
security definer
set search_path = public
as $$
  select e.kind, e.expires_at, e.source
  from public.entitlements e
  join public.profiles p on p.id = e.user_id
  where e.user_id = p_user_id
    and p.disabled_at is null
    and e.status = 'active'
    and e.starts_at <= now()
    and (e.expires_at is null or e.expires_at > now())
  order by case e.kind when 'lifetime' then 0 else 1 end, e.expires_at desc nulls first
  limit 1;
$$;

revoke all on function public.paxinbot_active_entitlement(uuid) from public, anon, authenticated;
