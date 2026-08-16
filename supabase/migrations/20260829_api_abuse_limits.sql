-- Paxinbot: contadores distribuídos para proteção contra abuso na API web.
-- A função retorna somente métricas operacionais; identificadores de IP,
-- usuário ou e-mail chegam ao banco exclusivamente como HMAC-SHA-256.

create index if not exists api_rate_limits_window_started_idx
  on public.api_rate_limits(window_started_at);

create or replace function public.paxinbot_service_rate_limit_v2(
  p_scope text,
  p_subject_hash text,
  p_limit integer,
  p_window_seconds integer,
  p_cost integer default 1
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_row public.api_rate_limits%rowtype;
  v_reset_after integer;
begin
  if p_scope !~ '^[a-z0-9_]{3,40}$'
     or p_subject_hash !~ '^[a-f0-9]{64}$'
     or p_limit not between 1 and 1000
     or p_window_seconds not between 10 and 86400
     or p_cost not between 1 and 100 then
    raise exception 'invalid_rate_limit';
  end if;

  insert into public.api_rate_limits(scope, subject_hash, window_started_at, hits)
  values (p_scope, p_subject_hash, now(), 0)
  on conflict (scope, subject_hash) do nothing;

  select * into v_row
  from public.api_rate_limits
  where scope = p_scope and subject_hash = p_subject_hash
  for update;

  if v_row.window_started_at + make_interval(secs => p_window_seconds) <= now() then
    update public.api_rate_limits
    set window_started_at = now(), hits = p_cost
    where scope = p_scope and subject_hash = p_subject_hash
    returning * into v_row;
  else
    update public.api_rate_limits
    set hits = hits + p_cost
    where scope = p_scope and subject_hash = p_subject_hash
    returning * into v_row;
  end if;

  v_reset_after := greatest(1, least(
    p_window_seconds,
    ceil(extract(epoch from (v_row.window_started_at + make_interval(secs => p_window_seconds) - now())))::integer
  ));

  -- Aproximadamente 1 em cada 256 sujeitos aciona uma limpeza leve. Como o
  -- valor é um HMAC secreto, um cliente não consegue escolher deliberadamente
  -- quando a coleta ocorre. Janelas de até 24 horas permanecem intactas.
  if get_byte(decode(substr(p_subject_hash, 1, 2), 'hex'), 0) = 0 then
    delete from public.api_rate_limits
    where window_started_at < now() - interval '2 days';
  end if;

  return jsonb_build_object(
    'allowed', v_row.hits <= p_limit,
    'remaining', greatest(0, p_limit - v_row.hits),
    'resetAfter', v_reset_after
  );
end;
$$;

revoke all on function public.paxinbot_service_rate_limit_v2(text,text,integer,integer,integer) from public, anon, authenticated;
grant execute on function public.paxinbot_service_rate_limit_v2(text,text,integer,integer,integer) to service_role;
