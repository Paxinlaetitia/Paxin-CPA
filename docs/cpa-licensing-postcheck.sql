-- Cash Hunters licensing: read-only post-deployment check for Supabase SQL Editor.
-- Inspects schema/RLS/ACL metadata only; it never reads customer rows.

begin transaction read only;

do $$
declare missing text[]:=array[]::text[];
begin
  select coalesce(array_agg(name),array[]::text[]) into missing from (values
    ('cpa_license_create_challenge(uuid,text,text,text)'),
    ('cpa_license_consume_challenge(uuid)'),
    ('cpa_license_register_proof(uuid,text)'),
    ('cpa_license_record_denial(text,text,text)'),
    ('cpa_license_activate(jsonb,text,text,text,text,text)'),
    ('cpa_license_refresh(text,text,text,text,text)'),
    ('cpa_license_authorize(text,text,text,text,text)'),
    ('cpa_license_logout(text,text,text)'),
    ('cpa_owner_list_licenses(text,text,integer)'),
    ('cpa_owner_list_license_audit(integer)'),
    ('cpa_owner_create_license(text,text,text,text,text,integer,timestamptz,text,uuid)'),
    ('cpa_owner_update_license(uuid,text,text,integer,timestamptz,text,text,text)'),
    ('cpa_owner_set_device_ban(text,boolean)')
  ) expected(name) where to_regprocedure('public.'||name) is null;
  if cardinality(missing)>0 then raise exception 'CPA postcheck missing RPCs: %',array_to_string(missing,', '); end if;
  if auth.role() is not null or public.paxinbot_is_owner() is true then
    raise exception 'CPA postcheck expected null service role and non-owner SQL Editor context';
  end if;
end;
$$;

with expected(name) as (values
  ('cpa_licenses'),('cpa_devices'),('cpa_device_bans'),('cpa_sessions'),('cpa_challenges'),('cpa_audit')
), table_security as (
  select e.name,c.relrowsecurity,
    has_table_privilege('anon',format('public.%I',e.name),'SELECT,INSERT,UPDATE,DELETE') as anon_data,
    has_table_privilege('authenticated',format('public.%I',e.name),'SELECT,INSERT,UPDATE,DELETE') as authenticated_data
  from expected e left join pg_catalog.pg_class c
    on c.relnamespace='public'::regnamespace and c.relname=e.name
)
select name as object_name,
  case when relrowsecurity is true and anon_data is false and authenticated_data is false then 'ok' else 'review' end as status,
  relrowsecurity as rls_enabled,anon_data,authenticated_data
from table_security order by name;

with rpc(signature,expected_role) as (values
  ('cpa_license_create_challenge(uuid,text,text,text)','service_role'),
  ('cpa_license_consume_challenge(uuid)','service_role'),
  ('cpa_license_register_proof(uuid,text)','service_role'),
  ('cpa_license_record_denial(text,text,text)','service_role'),
  ('cpa_license_activate(jsonb,text,text,text,text,text)','service_role'),
  ('cpa_license_refresh(text,text,text,text,text)','service_role'),
  ('cpa_license_authorize(text,text,text,text,text)','service_role'),
  ('cpa_license_logout(text,text,text)','service_role'),
  ('cpa_owner_list_licenses(text,text,integer)','authenticated'),
  ('cpa_owner_list_license_audit(integer)','authenticated'),
  ('cpa_owner_create_license(text,text,text,text,text,integer,timestamptz,text,uuid)','authenticated'),
  ('cpa_owner_update_license(uuid,text,text,integer,timestamptz,text,text,text)','authenticated'),
  ('cpa_owner_set_device_ban(text,boolean)','authenticated')
)
select signature,expected_role,
  has_function_privilege(expected_role,('public.'||signature)::regprocedure,'EXECUTE') as expected_execute,
  has_function_privilege('anon',('public.'||signature)::regprocedure,'EXECUTE') as anon_execute,
  case when expected_role='service_role' then has_function_privilege('authenticated',('public.'||signature)::regprocedure,'EXECUTE') else false end as unexpected_authenticated_execute
from rpc order by signature;

commit;
