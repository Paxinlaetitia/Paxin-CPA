begin;

-- O instalador não é um ativo público do site. A Vercel assina um endereço de
-- curta duração somente depois que o usuário possui uma sessão válida.
insert into storage.buckets (
  id,
  name,
  public,
  file_size_limit,
  allowed_mime_types
) values (
  'paxinbot-releases',
  'paxinbot-releases',
  false,
  157286400,
  array[
    'application/octet-stream',
    'application/x-msdownload',
    'application/vnd.microsoft.portable-executable'
  ]::text[]
)
on conflict (id) do update set
  public = false,
  file_size_limit = excluded.file_size_limit,
  allowed_mime_types = excluded.allowed_mime_types;

-- Nenhuma policy de storage.objects é criada de propósito. Upload, listagem e
-- exclusão continuam restritos ao backend de serviço e ao Dashboard Supabase.

commit;
