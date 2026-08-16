# Inventário de segredos do Paxinbot

Este documento registra nomes e finalidades. Ele nunca deve conter valores.

| Variável | Classificação | Finalidade | Production | Preview | Rotação |
| --- | --- | --- | --- | --- | --- |
| `SUPABASE_URL` | pública | URL base do projeto | projeto real | projeto de homologação | quando o projeto mudar |
| `SUPABASE_PUBLISHABLE_KEY` | pública | autenticação pública Supabase | projeto real | projeto de homologação | conforme Supabase |
| `SUPABASE_SECRET_KEY` | crítica | acesso privilegiado exclusivo da API | chave real | chave de homologação, nunca a real | após incidente ou mudança de acesso |
| `PAXINBOT_SESSION_SECRET` | crítica | assinatura e pseudonimização de sessões | exclusivo de Production | exclusivo de Preview | planejada, com invalidação de sessões |
| `MERCADOPAGO_ACCESS_TOKEN` | crítica | consulta e criação de pagamentos | produção | sandbox | após incidente ou revogação no provedor |
| `MERCADOPAGO_WEBHOOK_SECRET` | crítica | autenticação dos webhooks | produção | sandbox | junto da configuração do webhook |
| `RESEND_API_KEY` | crítica | envio transacional | chave restrita de produção | remetente/chave de teste | após incidente ou troca de escopo |
| `PAXINBOT_MODULE_CONTENT_KEY` | crítica | proteção de conteúdo do release | Production | ausente | a cada release protegido |
| `PAXINBOT_MODULE_AUTH_PRIVATE_KEY` | crítica | assinatura de autorização do release | Production | ausente | por cerimônia de rotação |
| `PAXINBOT_MODULE_AUTH_KEY_ID` | interna | identificação da chave pública | Production | ausente | junto da chave de assinatura |

## Regras obrigatórias

- Valores críticos ficam como **Sensitive** na Vercel.
- Nenhum segredo real de Production pode ter escopo Preview ou Development.
- O aplicativo e os arquivos públicos recebem somente URL, chave publicável e chaves públicas de verificação.
- Nenhum valor é enviado a tickets, commits, screenshots ou logs.
- Uma credencial não pode ser reutilizada para outra finalidade.
- Em incidente, primeiro revogue no provedor, depois substitua na Vercel e invalide as sessões relacionadas.

## Responsabilidade

O owner controla Cloudflare, Vercel, Supabase, Mercado Pago e Resend com MFA. A
aplicação valida presença e separação; os valores são criados e rotacionados nos
respectivos provedores.
