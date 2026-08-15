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

## Login seguro do aplicativo

O Paxinbot é tratado como um cliente público: o executável não contém a chave
secreta do Supabase, credenciais administrativas ou acesso direto às tabelas.
Ele inicia uma autorização curta, abre `https://www.paxincpa.store/activate` no
navegador e recebe somente uma sessão opaca de dispositivo depois da aprovação.

Antes de publicar a versão integrada, execute
`supabase/migrations/20260819_desktop_auth_hardening.sql` no SQL Editor. Essa
migração restringe os RPCs de dispositivo ao backend da Vercel, adiciona limites
de tentativas e reduz a sessão do aplicativo para sete dias. As variáveis
`SUPABASE_SECRET_KEY` e `PAXINBOT_SESSION_SECRET` devem existir somente na
Vercel. O arquivo `paxinbot-auth.json` distribuído com o aplicativo contém apenas
a URL pública do site.

## Checkout e liberação automática

O fluxo comercial usa Checkout Pro do Mercado Pago. Antes de habilitar compras em produção:

1. execute `supabase/migrations/20260817_checkout.sql` no SQL Editor do Supabase;
2. crie uma chave secreta exclusiva para o backend e salve-a na Vercel como `SUPABASE_SECRET_KEY`;
3. configure `MERCADOPAGO_ACCESS_TOKEN` e `MERCADOPAGO_WEBHOOK_SECRET` somente na Vercel;
4. no Mercado Pago, cadastre `https://www.paxincpa.store/api/webhooks/mercadopago` para eventos de pagamento;
5. para e-mails de confirmação, configure `RESEND_API_KEY` e `RESEND_FROM_EMAIL` com um domínio verificado.

## Pós-venda e atendimento

Após a migração de checkout, execute `supabase/migrations/20260818_aftercare.sql`. Ela adiciona:

- preferências de notificações da conta;
- histórico de eventos do cliente;
- detalhes, retomada de pedidos pendentes e recibo por e-mail;
- chamados de suporte com conversa entre cliente e owner;
- fila de atendimento, métricas e exportação de pedidos no painel administrativo.

O e-mail de resposta do atendimento é opcional e usa as mesmas variáveis `RESEND_API_KEY` e `RESEND_FROM_EMAIL`; o chamado continua disponível no portal mesmo quando o envio de e-mail não estiver configurado.

Nunca coloque chaves secretas em HTML, JavaScript do navegador ou no repositório. O retorno visual do checkout não concede acesso: somente o webhook assinado, depois de consultar o pagamento no Mercado Pago, pode criar o acesso.
