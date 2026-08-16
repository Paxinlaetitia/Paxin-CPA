# Segurança do site — pacote 1 de 9

O Pacote 1 separou as configurações públicas dos segredos usados pelo backend.
Ele não publicou o site nem configurou credenciais reais.

## Implementado

- inventário dos segredos e definição do local correto para cada um;
- bloqueio de arquivos `.env` locais no Git;
- exemplo de ambiente contendo somente nomes e valores demonstrativos;
- chave pública do Supabase separada da credencial secreta do servidor;
- operações de conta, módulos do aplicativo e webhook mantidos no backend;
- documentação de escopo para Vercel Preview e Production;
- teste automático contra exposição acidental de credenciais;
- logs estruturados sem registrar chaves, tokens ou senhas.

## Regra permanente

A chave publicável pode existir no navegador, mas depende de RLS e grants
mínimos. Credencial secreta do Supabase, token do Mercado Pago, segredo de
webhook, SMTP e chaves privadas existem apenas nos ambientes de servidor.

Consulte `secrets-inventory.md` antes de adicionar uma variável nova.
