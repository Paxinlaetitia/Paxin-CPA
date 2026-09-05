begin;

alter table public.profiles add column if not exists avatar_data text;
alter table public.profiles add constraint profiles_avatar_data_check check (
  avatar_data is null or (octet_length(avatar_data) <= 65559 and avatar_data ~ '^data:image/jpeg;base64,[A-Za-z0-9+/]+={0,2}$')
);
revoke update (avatar_data) on public.profiles from public, anon, authenticated;

create or replace function public.paxinbot_service_avatar(p_user_id uuid, p_action text, p_avatar_data text default null)
returns jsonb language plpgsql security definer set search_path=public,auth,pg_temp as $$
declare v_avatar text;
begin
  if auth.role() is distinct from 'service_role' then raise exception 'service_role_required'; end if;
  if p_action is null or p_action not in ('read','update','delete') then raise exception 'invalid_avatar_action'; end if;
  perform 1 from public.profiles where id=p_user_id and disabled_at is null for update;
  if not found then raise exception 'avatar_account_unavailable'; end if;
  if p_action='update' then
    if p_avatar_data is null or octet_length(p_avatar_data)>65559
      or p_avatar_data !~ '^data:image/jpeg;base64,[A-Za-z0-9+/]+={0,2}$' then raise exception 'invalid_avatar'; end if;
    update public.profiles set avatar_data=p_avatar_data where id=p_user_id;
    insert into public.audit_events(user_id,event_type) values(p_user_id,'account.avatar_updated');
  elsif p_action='delete' then
    update public.profiles set avatar_data=null where id=p_user_id;
    insert into public.audit_events(user_id,event_type) values(p_user_id,'account.avatar_removed');
  end if;
  select avatar_data into v_avatar from public.profiles where id=p_user_id;
  return jsonb_build_object('ok',true,'avatarData',v_avatar);
end;
$$;

revoke all on function public.paxinbot_service_avatar(uuid,text,text) from public,anon,authenticated;
grant execute on function public.paxinbot_service_avatar(uuid,text,text) to service_role;

commit;
