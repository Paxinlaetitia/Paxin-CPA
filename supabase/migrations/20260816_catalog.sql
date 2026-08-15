-- Catálogo de produtos ativos para clientes autenticados.
-- Retorna somente os campos necessários para exibir modalidades e preços.

create or replace function public.paxinbot_list_active_products()
returns jsonb
language plpgsql
stable
security definer
set search_path = public
as $$
begin
  return coalesce((
    select jsonb_agg(row_to_json(product_row) order by product_row."priceCents", product_row.name)
    from (
      select
        p.id,
        p.code,
        p.name,
        p.description,
        p.access_kind as "accessKind",
        p.duration_minutes as "durationMinutes",
        p.price_cents as "priceCents"
      from public.products p
      where p.active is true
    ) product_row
  ), '[]'::jsonb);
end;
$$;

revoke all on function public.paxinbot_list_active_products() from public;
grant execute on function public.paxinbot_list_active_products() to anon;
grant execute on function public.paxinbot_list_active_products() to authenticated;
