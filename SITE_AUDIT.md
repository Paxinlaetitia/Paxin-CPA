# Auditoria do site Paxinbot

Atualizada em 15/08/2026.

## Implementado e conectado

- Site institucional multipágina e responsivo.
- Cadastro, login por e-mail, confirmação de conta e recuperação de senha pelo Supabase.
- Login Google com sessão gravada em cookies `HttpOnly`.
- Base experimental de passkeys com alternativa por e-mail e Google.
- Área do Cliente autenticada com acesso, validade, segurança e download.
- Modalidades exibidas dentro da Área do Cliente.
- Autorização do aplicativo por código de dispositivo.
- Painel do proprietário protegido por validação no servidor.
- Cadastro de produtos, cupons e liberação manual de acesso.
- Busca funcional na Central de Ajuda.
- URLs públicas limpas e portais com navegação própria, sem sidebar.
- Configuração de conta, alteração de senha com reautenticação e fluxo de passkey.
- Gestão de dispositivos, pedidos, auditoria, preferências e histórico de atividades.
- Checkout Pro do Mercado Pago com pedido, retomada segura de pagamento pendente e liberação exclusiva por webhook assinado.
- Recibo opcional por e-mail e painel de chamados para cliente e owner.
- Painel administrativo com indicadores de receita/pedidos/atendimento, exportação de pedidos e resposta a chamados.

## Dependências externas ainda necessárias para venda

- Credenciais reais do Mercado Pago, webhook configurado e simulação de pagamentos em produção.
- Catálogo, preços e cupons reais, revisados antes de abrir as vendas.
- Arquivo final `PaxinbotSetup.exe` em armazenamento privado para download autorizado.
- SMTP transacional validado em produção para cadastro e recuperação de senha.
- Domínio de e-mail validado no Resend para notificações de pedido e suporte.
- Termos de Uso e Política de Privacidade definitivos, revisados antes da venda.

## Funcionalidades administrativas ainda parciais

- Suspender completamente uma conta de cliente.
- Processar estornos e reembolsos pelo provedor de pagamentos.
- Publicar e assinar novas versões do instalador.

## Validação antes do lançamento

- Testar cadastro, Google, recuperação e passkey em Chrome, Edge e celular.
- Confirmar que uma conta comum recebe `403` no endpoint administrativo.
- Confirmar que somente o proprietário visualiza o link Administração.
- Testar reflow em 320 px, navegação por teclado e foco visível.
- Validar o instalador e o fluxo completo de autorização do aplicativo.
- Simular pagamento aprovado, recusado, estornado e webhook repetido.
