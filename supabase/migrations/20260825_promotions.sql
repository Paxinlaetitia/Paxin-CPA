-- Paxinbot: campanhas promocionais administráveis e resgate idempotente.
-- Execute depois de 20260824_checkout_v1.sql.

create table if not exists public.promotions (
  id uuid primary key default extensions.gen_random_uuid(),
  code text not null unique check (code ~ '^[a-z0-9_-]{3,40}$'),
  name text not null check (char_length(name) between 3 and 80),
  headline text not null check (char_length(headline) between 3 and 120),
  description text not null default '' check (char_length(description) <= 500),
  audience text not null default 'new_accounts' check (audience in ('new_accounts','all_clients')),
  reward_seconds integer not null check (reward_seconds between 60 and 315360000),
  starts_at timestamptz,
  ends_at timestamptz,
  max_claims integer check (max_claims is null or max_claims > 0),
  active boolean not null default false,
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint promotion_period check (ends_at is null or starts_at is null or ends_at > starts_at)
);

create table if not exists public.promotion_claims (
  id uuid primary key default extensions.gen_random_uuid(),
  promotion_id uuid not null references public.promotions(id) on delete restrict,
  user_id uuid not null references auth.users(id) on delete cascade,
  usage_grant_id uuid not null references public.usage_grants(id) on delete restrict,
  device_fingerprint_hash text,
  claimed_at timestamptz not null default now(),
  unique (promotion_id,user_id)
);

create index if not exists promotion_claims_promotion_idx on public.promotion_claims(promotion_id,claimed_at desc);
create unique index if not exists promotion_claims_device_once_idx
  on public.promotion_claims(promotion_id,device_fingerprint_hash)
  where device_fingerprint_hash is not null;

alter table public.promotions enable row level security;
alter table public.promotion_claims enable row level security;
revoke all on table public.promotions, public.promotion_claims from public, anon, authenticated;

create or replace function public.paxinbot_list_my_promotions()
returns jsonb language plpgsql stable security definer set search_path = public, auth, pg_temp as $$
declare v_user auth.users%rowtype;
begin
  if auth.uid() is null then raise exception 'not_authenticated'; end if;
  select * into v_user from auth.users where id=auth.uid();
  if v_user.email_confirmed_at is null then return '[]'::jsonb; end if;
  if exists (select 1 from public.profiles where id=auth.uid() and disabled_at is not null) then return '[]'::jsonb; end if;

  return coalesce((select jsonb_agg(row_to_json(x) order by x."startsAt" nulls first,x."createdAt") from (
    select p.id,p.code,p.name,p.headline,p.description,p."rewardSeconds",p."startsAt",p."endsAt",p."createdAt"
    from (
      select pr.id,pr.code,pr.name,pr.headline,pr.description,
        pr.reward_seconds as "rewardSeconds",pr.starts_at as "startsAt",
        pr.ends_at as "endsAt",pr.created_at as "createdAt"
      from public.promotions pr
      where pr.active is true
        and (pr.starts_at is null or pr.starts_at<=now())
        and (pr.ends_at is null or pr.ends_at>now())
        and (pr.audience='all_clients' or v_user.created_at>=coalesce(pr.starts_at,pr.created_at))
        and not exists (select 1 from public.promotion_claims pc where pc.promotion_id=pr.id and pc.user_id=auth.uid())
        and (pr.max_claims is null or (select count(*) from public.promotion_claims pc where pc.promotion_id=pr.id)<pr.max_claims)
    ) p
  ) x), '[]'::jsonb);
end;
$$;

create or replace function public.paxinbot_claim_promotion(p_promotion_id uuid)
returns jsonb language plpgsql security definer set search_path = public, auth, pg_temp as $$
declare v_user auth.users%rowtype; v_promotion public.promotions%rowtype; v_grant public.usage_grants%rowtype; v_claim public.promotion_claims%rowtype;
begin
  if auth.uid() is null then raise exception 'not_authenticated'; end if;
  select * into v_user from auth.users where id=auth.uid();
  if v_user.email_confirmed_at is null then raise exception 'email_not_confirmed'; end if;
  if exists (select 1 from public.profiles where id=auth.uid() and disabled_at is not null) then raise exception 'account_disabled'; end if;

  select * into v_promotion from public.promotions where id=p_promotion_id for update;
  if not found or not v_promotion.active
    or (v_promotion.starts_at is not null and v_promotion.starts_at>now())
    or (v_promotion.ends_at is not null and v_promotion.ends_at<=now()) then
    raise exception 'promotion_unavailable';
  end if;
  if v_promotion.audience='new_accounts' and v_user.created_at<coalesce(v_promotion.starts_at,v_promotion.created_at) then
    raise exception 'promotion_not_eligible';
  end if;

  select * into v_claim from public.promotion_claims where promotion_id=v_promotion.id and user_id=auth.uid();
  if found then
    select * into v_grant from public.usage_grants where id=v_claim.usage_grant_id;
    return jsonb_build_object('claimed',true,'alreadyClaimed',true,'promotionId',v_promotion.id,
      'grantId',v_grant.id,'remainingSeconds',v_grant.remaining_seconds,'status',v_grant.status);
  end if;
  if v_promotion.max_claims is not null and
    (select count(*) from public.promotion_claims where promotion_id=v_promotion.id)>=v_promotion.max_claims then
    raise exception 'promotion_limit_reached';
  end if;

  insert into public.usage_grants(user_id,total_seconds,remaining_seconds,source)
    values(auth.uid(),v_promotion.reward_seconds,v_promotion.reward_seconds,'promotion:'||v_promotion.code)
    returning * into v_grant;
  insert into public.promotion_claims(promotion_id,user_id,usage_grant_id)
    values(v_promotion.id,auth.uid(),v_grant.id);
  insert into public.audit_events(user_id,event_type,metadata)
    values(auth.uid(),'promotion.claimed',jsonb_build_object('promotionId',v_promotion.id,'code',v_promotion.code,'grantId',v_grant.id,'rewardSeconds',v_promotion.reward_seconds));
  return jsonb_build_object('claimed',true,'alreadyClaimed',false,'promotionId',v_promotion.id,
    'grantId',v_grant.id,'remainingSeconds',v_grant.remaining_seconds,'status',v_grant.status);
end;
$$;

create or replace function public.paxinbot_owner_list_promotions()
returns jsonb language plpgsql stable security definer set search_path = public, auth, pg_temp as $$
begin
  perform public.paxinbot_require_owner();
  return coalesce((select jsonb_agg(row_to_json(x) order by x.created_at desc) from (
    select p.id,p.code,p.name,p.headline,p.description,p.audience,p.reward_seconds,p.starts_at,p.ends_at,
      p.max_claims,p.active,p.created_at,p.updated_at,(select count(*) from public.promotion_claims pc where pc.promotion_id=p.id) as claims
    from public.promotions p
  ) x), '[]'::jsonb);
end;
$$;

create or replace function public.paxinbot_owner_save_promotion(
  p_id uuid,p_code text,p_name text,p_headline text,p_description text,p_audience text,
  p_reward_seconds integer,p_starts_at timestamptz,p_ends_at timestamptz,p_max_claims integer,p_active boolean
)
returns jsonb language plpgsql security definer set search_path = public, auth, pg_temp as $$
declare v_promotion public.promotions%rowtype;
begin
  perform public.paxinbot_require_owner();
  p_code:=lower(trim(coalesce(p_code,''))); p_name:=trim(coalesce(p_name,'')); p_headline:=trim(coalesce(p_headline,''));
  if p_code !~ '^[a-z0-9_-]{3,40}$' then raise exception 'invalid_promotion_code'; end if;
  if char_length(p_name) not between 3 and 80 or char_length(p_headline) not between 3 and 120 then raise exception 'invalid_promotion_text'; end if;
  if char_length(coalesce(p_description,''))>500 then raise exception 'invalid_promotion_description'; end if;
  if p_audience not in ('new_accounts','all_clients') then raise exception 'invalid_promotion_audience'; end if;
  if p_reward_seconds not between 60 and 315360000 then raise exception 'invalid_promotion_reward'; end if;
  if p_max_claims is not null and p_max_claims<1 then raise exception 'invalid_promotion_limit'; end if;
  if p_starts_at is not null and p_ends_at is not null and p_ends_at<=p_starts_at then raise exception 'invalid_promotion_period'; end if;

  if p_id is null then
    insert into public.promotions(code,name,headline,description,audience,reward_seconds,starts_at,ends_at,max_claims,active,created_by)
      values(p_code,p_name,p_headline,coalesce(p_description,''),p_audience,p_reward_seconds,p_starts_at,p_ends_at,p_max_claims,coalesce(p_active,false),auth.uid())
      returning * into v_promotion;
  else
    update public.promotions set code=p_code,name=p_name,headline=p_headline,description=coalesce(p_description,''),
      audience=p_audience,reward_seconds=p_reward_seconds,starts_at=p_starts_at,ends_at=p_ends_at,
      max_claims=p_max_claims,active=coalesce(p_active,false),updated_at=now()
      where id=p_id returning * into v_promotion;
    if not found then raise exception 'promotion_not_found'; end if;
  end if;
  insert into public.audit_events(user_id,event_type,metadata)
    values(auth.uid(),'owner.promotion_saved',jsonb_build_object('promotionId',v_promotion.id,'code',v_promotion.code,'active',v_promotion.active));
  return to_jsonb(v_promotion);
end;
$$;

revoke all on function public.paxinbot_list_my_promotions() from public;
revoke all on function public.paxinbot_claim_promotion(uuid) from public;
revoke all on function public.paxinbot_owner_list_promotions() from public;
revoke all on function public.paxinbot_owner_save_promotion(uuid,text,text,text,text,text,integer,timestamptz,timestamptz,integer,boolean) from public;
grant execute on function public.paxinbot_list_my_promotions() to authenticated;
grant execute on function public.paxinbot_claim_promotion(uuid) to authenticated;
grant execute on function public.paxinbot_owner_list_promotions() to authenticated;
grant execute on function public.paxinbot_owner_save_promotion(uuid,text,text,text,text,text,integer,timestamptz,timestamptz,integer,boolean) to authenticated;

insert into public.promotions(code,name,headline,description,audience,reward_seconds,active)
values('boas-vindas-1h','Presente de boas-vindas','Você ganhou 1 hora de Paxinbot',
  'Resgate o presente agora. O tempo continuará pausado até ser ativado no aplicativo.',
  'new_accounts',3600,false)
on conflict (code) do nothing;
