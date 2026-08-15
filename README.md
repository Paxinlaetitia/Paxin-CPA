# Paxinbot Site

Site institucional e Área do Cliente do Paxinbot.

## Visualizar

Abra `index.html` em um navegador moderno ou use o atalho `Visualizar Paxinbot Site` criado na Área de Trabalho.

## Escopo desta versão

- Identidade visual alinhada ao aplicativo Paxinbot.
- Landing page responsiva.
- Navegação multipágina com Início, Produto, Recursos, Planos, Segurança e Ajuda.
- Área do Cliente conectada às rotas de autenticação da Vercel/Supabase.
- Página de Download com versão, requisitos, instalação e notas da versão.
- Descrições baseadas nas funções existentes do aplicativo: telas, instâncias, controle operacional, fluxos, contas, dados, proxies, SMS, Auto Click e logs.
- Explicação do modelo CPA e aviso de uso responsável, sem promessas de aprovação ou retorno financeiro.
- Estrutura de recursos, funcionamento, planos, segurança, perguntas e download.
- Rotas de login, sessão, recuperação de senha e autorização de computador.
- Estrutura para banco Supabase e acesso por duração/vitalício.

O backend de produção usa Vercel Functions e Supabase. Antes da venda, configure SMTP, conecte o provedor de pagamentos, publique o instalador e conclua os itens listados em `SITE_AUDIT.md`.

Para ativar gerenciamento de perfil, dispositivos, pedidos e auditoria nos novos portais, execute no SQL Editor do Supabase a migração `supabase/migrations/20260815_portals.sql` após a migração principal de acesso.

Para listar automaticamente na aba Assinatura os produtos ativos cadastrados pelo owner, execute também `supabase/migrations/20260816_catalog.sql`.
