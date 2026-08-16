# Pacote de segurança 1

O inventário detalhado deste pacote está em `SECURITY_PACKAGES.md` no código do
aplicativo. No site, o pacote adiciona a migração
`20260826_device_identity.sql`, os RPCs de autorização v3 e o gerenciamento de
dispositivos no painel do proprietário.

Ordem obrigatória de ativação:

1. aplicar `20260825_promotions.sql` no Supabase;
2. aplicar `20260826_device_identity.sql` no Supabase;
3. publicar o site com os endpoints v3;
4. distribuir o aplicativo que envia a prova assinada.

Não publique somente uma parte: os endpoints v3 falham de forma segura quando a
migração correspondente ainda não existe.
