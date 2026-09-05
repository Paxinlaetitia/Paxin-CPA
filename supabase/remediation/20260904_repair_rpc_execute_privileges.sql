-- Paxinbot: reparar permissoes RPC apontadas pelo Security Advisor.
-- Correcao MANUAL de ACL existentes; nao e migracao automatica de publicacao.
-- PREPARADO LOCALMENTE; executar somente apos revisar a auditoria.
-- Requer as migracoes anteriores ate 20260903 e o papel postgres.
-- Nao altera dados, politicas RLS, corpos de funcoes, auth ou storage.
-- Assinaturas completas: sobrecargas desconhecidas NAO recebem permissao.
begin;
set local lock_timeout = '5s';
set local statement_timeout = '30s';
set local search_path = pg_catalog, public, pg_temp;

create temporary table paxinbot_rpc_acl_20260904 (
  signature text primary key,
  allow_anon boolean not null,
  allow_authenticated boolean not null,
  allow_service boolean not null,
  required boolean not null
) on commit drop;
insert into pg_temp.paxinbot_rpc_acl_20260904 values
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
  ('public.paxinbot_update_my_profile(text)', false, true, false, true);

do $repair$
declare
  v_missing text;
  v_function record;
  v_expected record;
  v_oid oid;
  v_signature text;
begin
  if current_user <> 'postgres' then
    raise exception 'Execute como postgres no SQL Editor; nenhuma permissao foi alterada.';
  end if;
  select string_agg(signature, ', ' order by signature) into v_missing
  from pg_temp.paxinbot_rpc_acl_20260904
  where required and to_regprocedure(signature) is null;
  if v_missing is not null then
    raise exception 'Faltam funcoes de migracoes anteriores. Pare e revise: %', v_missing;
  end if;

  -- Remove tambem grants diretos, nao apenas os herdados de PUBLIC.
  -- Funcoes internas continuam sendo chamadas pelo proprietario dos definers.
  for v_function in
    select p.oid, n.nspname, p.proname, pg_get_function_identity_arguments(p.oid) as arguments
    from pg_proc p join pg_namespace n on n.oid = p.pronamespace
    where n.nspname = 'public'
      and p.prokind = 'f'
      and (left(p.proname, 9) = 'paxinbot_' or p.proname = 'handle_new_auth_user')
  loop
    execute format('revoke execute on function %I.%I(%s) from public, anon, authenticated, service_role',
      v_function.nspname, v_function.proname, v_function.arguments);
  end loop;

  for v_expected in select * from pg_temp.paxinbot_rpc_acl_20260904 loop
    v_oid := to_regprocedure(v_expected.signature);
    if v_oid is null then continue; end if; -- somente sobrecarga antiga opcional
    select format('%I.%I(%s)', n.nspname, p.proname, pg_get_function_identity_arguments(p.oid))
      into v_signature
    from pg_proc p join pg_namespace n on n.oid = p.pronamespace where p.oid = v_oid;
    if v_expected.allow_anon then
      execute format('grant execute on function %s to anon', v_signature);
    end if;
    if v_expected.allow_authenticated then
      execute format('grant execute on function %s to authenticated', v_signature);
    end if;
    if v_expected.allow_service then
      execute format('grant execute on function %s to service_role', v_signature);
    end if;
  end loop;

  -- Confere privilegios EFETIVOS (inclui heranca). Qualquer divergencia aborta
  -- a transacao; nao tenta remover memberships nem usar CASCADE.
  for v_function in
    select p.oid, p.oid::regprocedure::text as signature,
      coalesce(a.allow_anon, false) as allow_anon,
      coalesce(a.allow_authenticated, false) as allow_authenticated,
      coalesce(a.allow_service, false) as allow_service
    from pg_proc p join pg_namespace n on n.oid = p.pronamespace
    left join pg_temp.paxinbot_rpc_acl_20260904 a on to_regprocedure(a.signature) = p.oid
    where n.nspname = 'public'
      and p.prokind = 'f'
      and (left(p.proname, 9) = 'paxinbot_' or p.proname = 'handle_new_auth_user')
  loop
    if has_function_privilege('anon', v_function.oid, 'EXECUTE') <> v_function.allow_anon
      or has_function_privilege('authenticated', v_function.oid, 'EXECUTE') <> v_function.allow_authenticated
      or has_function_privilege('service_role', v_function.oid, 'EXECUTE') <> v_function.allow_service
      or exists (
        select 1 from pg_proc p,
          lateral aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) acl
        where p.oid = v_function.oid and acl.grantee = 0 and acl.privilege_type = 'EXECUTE'
      )
    then
      raise exception 'Permissao inesperada em %. Transacao cancelada; revise grants e memberships.', v_function.signature;
    end if;
  end loop;
end;
$repair$;
commit;
