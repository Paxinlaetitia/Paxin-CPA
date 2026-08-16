-- Paxinbot: índices focados nas leituras mais frequentes da Área do Cliente.
-- Pode ser reaplicado com segurança depois de 20260831_database_least_privilege.sql.

create index if not exists desktop_sessions_user_last_seen_idx
  on public.desktop_sessions (user_id, last_seen_at desc);

create index if not exists desktop_sessions_user_active_idx
  on public.desktop_sessions (user_id, expires_at desc)
  where revoked_at is null;

create index if not exists audit_events_user_created_idx
  on public.audit_events (user_id, created_at desc);
