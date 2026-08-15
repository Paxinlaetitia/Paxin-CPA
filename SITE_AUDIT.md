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
- Gestão de dispositivos, pedidos e auditoria preparada pela migração `20260815_portals.sql`.

## Dependências externas ainda necessárias para venda

- Provedor de pagamento e webhook para criar pedidos e liberar acesso automaticamente.
- Checkout com preços reais, cupons e confirmação de pagamento.
- Arquivo final `PaxinbotSetup.exe` em armazenamento privado para download autorizado.
- SMTP transacional validado em produção para cadastro e recuperação de senha.
- Canal de suporte real (e-mail, formulário ou plataforma de atendimento).
- Termos de Uso e Política de Privacidade definitivos, revisados antes da venda.

## Funcionalidades administrativas ainda parciais

- Suspender completamente uma conta de cliente.
- Processar estornos e reembolsos pelo provedor de pagamentos.
- Publicar e assinar novas versões do instalador.
- Abrir e responder solicitações de suporte dentro do portal.
- Publicar o catálogo administrado no checkout e na Área do Cliente.

## Validação antes do lançamento

- Testar cadastro, Google, recuperação e passkey em Chrome, Edge e celular.
- Confirmar que uma conta comum recebe `403` no endpoint administrativo.
- Confirmar que somente o proprietário visualiza o link Administração.
- Testar reflow em 320 px, navegação por teclado e foco visível.
- Validar o instalador e o fluxo completo de autorização do aplicativo.
- Simular pagamento aprovado, recusado, estornado e webhook repetido.
