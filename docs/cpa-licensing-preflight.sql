-- Cash Hunters licensing: read-only preflight for Supabase SQL Editor.
-- Returns metadata only; it never reads customer rows or changes the database.

begin transaction read only;

do $$
declare missing text[]:=array[]::text[];
begin
  if to_regclass('auth.users') is null then missing:=missing||'auth.users'; end if;
  if to_regprocedure('public.paxinbot_is_owner()') is null then missing:=missing||'public.paxinbot_is_owner()'; end if;
  if to_regprocedure('public.paxinbot_service_rate_limit(text,text,integer,integer)') is null then
    missing:=missing||'public.paxinbot_service_rate_limit(text,text,integer,integer)';
  end if;
  if to_regprocedure('extensions.gen_random_uuid()') is null then missing:=missing||'extensions.gen_random_uuid()'; end if;
  if cardinality(missing)>0 then raise exception 'CPA preflight missing prerequisites: %',array_to_string(missing,', '); end if;
end;
$$;

with expected(name) as (values
  ('cpa_licenses'),('cpa_devices'),('cpa_device_bans'),('cpa_sessions'),('cpa_challenges'),('cpa_audit')
)
select e.name as object_name,
  case when c.oid is null then 'available' else 'already_exists_review_before_migration' end as status
from expected e left join pg_catalog.pg_class c
  on c.relnamespace='public'::regnamespace and c.relname=e.name
order by e.name;

commit;
