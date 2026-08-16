# Segurança do site — pacote 4

O Pacote 4 endurece a fronteira entre navegador, Cloudflare, Vercel e APIs do
Paxinbot. Nada deste pacote é publicado automaticamente.

## Implementado

- APIs recusam, em produção, hosts diferentes do domínio oficial;
- previews aceitam somente o host exato fornecido pela própria Vercel;
- `PUBLIC_SITE_URL` passa a ser obrigatório e estritamente HTTPS em produção;
- CSP promovida de observação para bloqueio, sem JavaScript inline;
- políticas adicionais de isolamento de abertura e recursos entre origens;
- páginas autenticadas, callbacks, ativação e APIs marcadas como `no-store`;
- páginas sensíveis marcadas como `noindex`;
- documentação, testes, migrações e arquivos locais removidos do pacote Vercel;
- guia cumulativo e reversível para ativar a Cloudflare por etapas.

O `style-src 'unsafe-inline'` permanece exclusivamente porque o componente de
calendário e seleção calcula posição e altura em tempo de execução. Scripts
inline, `eval` e objetos incorporados continuam proibidos.

## Validação antes de produção

1. implantar somente na branch de preview;
2. testar login por senha e Google, cadastro e recuperação;
3. testar passkey, checkout PIX/cartão e webhook do Mercado Pago;
4. testar autorização, polling e sessão do aplicativo;
5. verificar no navegador que não existem violações de CSP;
6. conferir que `/tests/`, `/docs/` e `/supabase/` retornam `404`;
7. somente depois seguir `cloudflare-activation-guide.md`.
