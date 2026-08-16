-- Paxinbot: banco opt-in e superfície Data API mínima.
-- Execute depois de 20260830_site_security_observability.sql.

begin;

-- Nenhum papel chamado pela Data API pode criar objetos capazes de sombrear
-- nomes usados por funções SECURITY DEFINER com search_path fixo em public.
revoke create on schema public from public, anon, authenticated, service_role;
grant usage on schema public to anon, authenticated, service_role;

-- Projetos antigos do Supabase podem conceder acesso automático a objetos
-- novos. A partir desta migração, toda exposição precisa de grant explícito.
alter default privileges for role postgres in schema public
  revoke all on tables from public, anon, authenticated, service_role;
alter default privileges for role postgres in schema public
  revoke execute on functions from public, anon, authenticated, service_role;
alter default privileges for role postgres in schema public
  revoke usage, select on sequences from public, anon, authenticated, service_role;

-- O Paxinbot acessa dados por RPCs validados. Elimine acesso direto legado,
-- inclusive para a chave secreta; funções SECURITY DEFINER continuam usando
-- os privilégios do proprietário da função.
revoke all privileges on all tables in schema public from public, anon, authenticated, service_role;
revoke all privileges on all sequences in schema public from public, anon, authenticated, service_role;
revoke execute on all functions in schema public from public, anon, authenticated, service_role;

-- Leitura mínima usada pelo servidor para mostrar se um saldo está rodando.
-- Substitui a consulta REST direta à tabela desktop_sessions.
create or replace function public.paxinbot_get_usage_runtime_state(
  p_user_id uuid,
  p_usage_grant_id uuid
)
returns jsonb language plpgsql stable security definer
set search_path=public,auth,pg_temp as $$
declare v_running boolean := false;
begin
  if auth.role() <> 'service_role' then raise exception 'service_role_required'; end if;
  if p_user_id is null or p_usage_grant_id is null then raise exception 'runtime_query_invalid'; end if;
  select exists(
    select 1 from public.desktop_sessions s
    where s.user_id=p_user_id and s.usage_grant_id=p_usage_grant_id
      and s.revoked_at is null and s.usage_paused_at is null
      and s.last_seen_at > now() - interval '25 seconds'
  ) into v_running;
  return jsonb_build_object('running',v_running);
end;
$$;

-- Reabra somente os RPCs chamados sem sessão.
do $block$
declare v_signature regprocedure;
begin
  for v_signature in
    select p.oid::regprocedure
    from pg_proc p join pg_namespace n on n.oid=p.pronamespace
    where n.nspname='public' and p.proname=any(array[
      'paxinbot_list_active_products'
    ])
  loop execute format('grant execute on function %s to anon',v_signature); end loop;
end;
$block$;

-- RPCs do navegador autenticado. Funções owner continuam verificando o owner
-- dentro do banco; receber EXECUTE não concede o resultado privilegiado.
do $block$
declare v_signature regprocedure;
begin
  for v_signature in
    select p.oid::regprocedure
    from pg_proc p join pg_namespace n on n.oid=p.pronamespace
    where n.nspname='public' and p.proname=any(array[
      'paxinbot_list_active_products','paxinbot_get_my_account',
      'paxinbot_list_my_devices','paxinbot_revoke_my_device',
      'paxinbot_revoke_all_my_devices','paxinbot_update_my_profile',
      'paxinbot_list_my_orders','paxinbot_get_my_preferences',
      'paxinbot_update_my_preferences','paxinbot_list_my_activity',
      'paxinbot_get_my_order','paxinbot_get_my_receipt',
      'paxinbot_resume_checkout','paxinbot_create_support_ticket',
      'paxinbot_reply_support_ticket','paxinbot_list_my_support_tickets',
      'paxinbot_get_my_access','paxinbot_list_my_usage_grants',
      'paxinbot_activate_usage_grant','paxinbot_list_my_promotions',
      'paxinbot_claim_promotion','paxinbot_quote_checkout',
      'paxinbot_prepare_checkout_v2','paxinbot_attach_checkout_preference',
      'paxinbot_attach_pix_order','paxinbot_get_checkout_status',
      'paxinbot_is_owner','paxinbot_owner_overview',
      'paxinbot_owner_list_users','paxinbot_owner_list_products',
      'paxinbot_owner_save_product','paxinbot_owner_list_coupons',
      'paxinbot_owner_save_coupon','paxinbot_owner_list_promotions',
      'paxinbot_owner_save_promotion','paxinbot_owner_grant_access',
      'paxinbot_owner_grant_usage','paxinbot_owner_revoke_access',
      'paxinbot_owner_list_orders','paxinbot_owner_list_audit',
      'paxinbot_owner_list_support_tickets','paxinbot_owner_reply_support_ticket',
      'paxinbot_owner_update_support_status',
      'paxinbot_owner_list_device_identities','paxinbot_owner_set_device_ban',
      'paxinbot_owner_list_security_risk','paxinbot_owner_reset_security_risk',
      'paxinbot_owner_list_site_security_events'
    ])
  loop execute format('grant execute on function %s to authenticated',v_signature); end loop;
end;
$block$;

-- RPCs exclusivos da Vercel usando a chave secreta. Versões v2 e funções
-- internas antigas permanecem sem EXECUTE pela Data API.
do $block$
declare v_signature regprocedure;
begin
  for v_signature in
    select p.oid::regprocedure
    from pg_proc p join pg_namespace n on n.oid=p.pronamespace
    where n.nspname='public' and p.proname=any(array[
      'paxinbot_service_rate_limit','paxinbot_service_rate_limit_v2',
      'paxinbot_device_start_v3','paxinbot_device_approve_v3',
      'paxinbot_device_poll_v3','paxinbot_desktop_session_v3',
      'paxinbot_pause_desktop_usage_v3','paxinbot_record_security_event',
      'paxinbot_record_device_security_event',
      'paxinbot_authorize_protected_release',
      'paxinbot_finalize_mercadopago_payment',
      'paxinbot_record_site_security_event',
      'paxinbot_get_usage_runtime_state'
    ])
  loop execute format('grant execute on function %s to service_role',v_signature); end loop;
end;
$block$;

commit;
