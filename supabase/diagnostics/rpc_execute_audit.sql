-- SOMENTE LEITURA. Execute antes e depois da correcao e exporte o resultado.
-- Nao mostra chaves, sessoes, usuarios ou dados comerciais.
-- expected = contrato da versao atual do site; MISSING exige revisar migracoes.
with expected(signature, allow_anon, allow_authenticated, allow_service, required) as (
 values
  ('public.paxinbot_activate_usage_grant(uuid)', false, true, false, true),
  ('public.paxinbot_attach_checkout_preference(uuid,text)', false, true, false, true),
  ('public.paxinbot_attach_pix_order(uuid,text,text,timestamptz)', false, true, false, true),
  ('public.paxinbot_authorize_protected_release(text,text,integer,text,text,text)', false, false, true, true),
  ('public.paxinbot_claim_promotion(uuid)', false, true, false, true),
  ('public.paxinbot_create_support_ticket(text,text,text)', false, true, false, true),
  ('public.paxinbot_desktop_session_v3(text)', false, false, true, true),
  ('public.paxinbot_device_approve_v3(uuid,text,uuid)', false, false, true, true),
  ('public.paxinbot_device_poll_v3(uuid,text)', false, false, true, true),
  ('public.paxinbot_device_start_v3(uuid,text,text,text,text,text,text,text,text,text,text)', false, false, true, true),
  ('public.paxinbot_finalize_mercadopago_payment(text,text,text,integer,text,jsonb)', false, false, true, true),
  ('public.paxinbot_get_checkout_status(uuid)', false, true, false, true),
  ('public.paxinbot_get_my_access()', false, true, false, true),
  ('public.paxinbot_get_my_account()', false, true, false, true),
  ('public.paxinbot_get_my_order(uuid)', false, true, false, true),
  ('public.paxinbot_get_my_preferences()', false, true, false, true),
  ('public.paxinbot_get_my_receipt(uuid)', false, true, false, true),
  ('public.paxinbot_get_usage_runtime_state(uuid,uuid)', false, false, true, true),
  ('public.paxinbot_is_owner()', false, true, false, true),
  ('public.paxinbot_list_active_products()', true, true, false, true),
  ('public.paxinbot_list_my_activity()', false, true, false, true),
  ('public.paxinbot_list_my_devices()', false, true, false, true),
  ('public.paxinbot_list_my_orders()', false, true, false, true),
  ('public.paxinbot_list_my_promotions()', false, true, false, true),
  ('public.paxinbot_list_my_support_tickets()', false, true, false, true),
  ('public.paxinbot_list_my_usage_grants()', false, true, false, true),
  ('public.paxinbot_owner_approve_order(uuid)', false, true, false, true),
  ('public.paxinbot_owner_grant_access(text,text,timestamptz,text)', false, true, false, true),
  ('public.paxinbot_owner_grant_usage(text,integer,text)', false, true, false, true),
  ('public.paxinbot_owner_kick_user(uuid)', false, true, false, true),
  ('public.paxinbot_owner_list_audit()', false, true, false, true),
  ('public.paxinbot_owner_list_coupons()', false, true, false, true),
  ('public.paxinbot_owner_list_device_identities(text)', false, true, false, true),
  ('public.paxinbot_owner_list_orders()', false, true, false, false),
  ('public.paxinbot_owner_list_orders(text)', false, true, false, true),
  ('public.paxinbot_owner_list_products()', false, true, false, true),
  ('public.paxinbot_owner_list_promotions()', false, true, false, true),
  ('public.paxinbot_owner_list_security_risk(text)', false, true, false, true),
  ('public.paxinbot_owner_list_site_security_events(integer)', false, true, false, true),
  ('public.paxinbot_owner_list_support_tickets()', false, true, false, true),
  ('public.paxinbot_owner_list_users(text)', false, true, false, true),
  ('public.paxinbot_owner_overview()', false, true, false, true),
  ('public.paxinbot_owner_refund_order(uuid)', false, true, false, true),
  ('public.paxinbot_owner_reply_support_ticket(uuid,text)', false, true, false, true),
  ('public.paxinbot_owner_reset_security_risk(uuid)', false, true, false, true),
  ('public.paxinbot_owner_reset_user_devices(uuid)', false, true, false, true),
  ('public.paxinbot_owner_revoke_access(uuid)', false, true, false, true),
  ('public.paxinbot_owner_save_coupon(uuid,text,text,text,integer,integer,timestamptz,boolean)', false, true, false, true),
  ('public.paxinbot_owner_save_product(uuid,text,text,text,text,integer,integer,boolean)', false, true, false, true),
  ('public.paxinbot_owner_save_promotion(uuid,text,text,text,text,text,integer,timestamptz,timestamptz,integer,boolean)', false, true, false, true),
  ('public.paxinbot_owner_set_device_ban(uuid,boolean,text)', false, true, false, true),
  ('public.paxinbot_owner_set_user_ban(uuid,boolean,text)', false, true, false, true),
  ('public.paxinbot_owner_update_support_status(uuid,text)', false, true, false, true),
  ('public.paxinbot_pause_desktop_usage_v3(text)', false, false, true, true),
  ('public.paxinbot_prepare_checkout_v2(uuid,text,uuid,text,text)', false, true, false, true),
  ('public.paxinbot_quote_checkout(uuid,text)', false, true, false, true),
  ('public.paxinbot_record_device_security_event(text,text,uuid,text,text)', false, false, true, true),
  ('public.paxinbot_record_security_event(text,uuid,text,timestamptz,text,integer,jsonb)', false, false, true, true),
  ('public.paxinbot_record_site_security_event(uuid,uuid,text,smallint,text,uuid,text,text,jsonb)', false, false, true, true),
  ('public.paxinbot_reply_support_ticket(uuid,text)', false, true, false, true),
  ('public.paxinbot_resume_checkout(uuid)', false, true, false, true),
  ('public.paxinbot_revoke_all_my_devices()', false, true, false, true),
  ('public.paxinbot_revoke_my_device(uuid)', false, true, false, true),
  ('public.paxinbot_service_rate_limit_v2(text,text,integer,integer,integer)', false, false, true, true),
  ('public.paxinbot_service_rate_limit(text,text,integer,integer)', false, false, true, true),
  ('public.paxinbot_update_my_preferences(boolean,boolean)', false, true, false, true),
  ('public.paxinbot_update_my_profile(text)', false, true, false, true)
), actual as (
  select p.oid, p.oid::regprocedure::text as signature,
    pg_get_userbyid(p.proowner) as owner, p.prosecdef as security_definer,
    p.proacl::text as acl_snapshot,
    has_function_privilege('anon', p.oid, 'EXECUTE') as anon_execute,
    has_function_privilege('authenticated', p.oid, 'EXECUTE') as authenticated_execute,
    has_function_privilege('service_role', p.oid, 'EXECUTE') as service_execute,
    exists (
      select 1 from aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) acl
      where acl.grantee = 0 and acl.privilege_type = 'EXECUTE'
    ) as public_execute
  from pg_proc p join pg_namespace n on n.oid = p.pronamespace
  where n.nspname = 'public'
      and p.prokind = 'f'
      and (left(p.proname, 9) = 'paxinbot_' or p.proname = 'handle_new_auth_user')
)
select coalesce(a.signature, e.signature) as function_signature,
  case when a.oid is null and e.required then 'MISSING'
    when a.oid is null then 'OPTIONAL_ABSENT'
    when a.public_execute
      or a.anon_execute <> coalesce(e.allow_anon, false)
      or a.authenticated_execute <> coalesce(e.allow_authenticated, false)
      or a.service_execute <> coalesce(e.allow_service, false) then 'REVIEW'
    else 'OK' end as status,
  a.owner, a.security_definer, a.public_execute,
  a.anon_execute, coalesce(e.allow_anon, false) as expected_anon,
  a.authenticated_execute, coalesce(e.allow_authenticated, false) as expected_authenticated,
  a.service_execute, coalesce(e.allow_service, false) as expected_service,
  a.acl_snapshot
from actual a full join expected e on a.oid = to_regprocedure(e.signature)
order by status, function_signature;
