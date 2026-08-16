# Segurança do site — pacote 8 de 9

O Pacote 8 prepara contenção, rotação e recuperação e adiciona uma barreira
opcional entre Cloudflare e as APIs da Vercel. Nada foi ativado ou publicado.

## Implementado

- Worker de origem que remove qualquer cabeçalho enviado pelo cliente e injeta
  um segredo armazenado como Secret binding;
- validação em tempo constante desse segredo nas APIs de produção;
- origem protegida permanece opt-in e previews da Vercel continuam funcionando;
- rotação do segredo de origem com sobreposição máxima de 48 horas;
- rotação equivalente para assinatura do webhook do Mercado Pago;
- política pública de divulgação responsável;
- runbook com severidade, contenção, rotação, rollback, recuperação,
  comunicação e pós-incidente;
- material operacional excluído do pacote público da Vercel.

## Ordem de ativação futura

Somente depois do Pacote 9 e do preview aprovado:

1. criar um segredo aleatório de no mínimo 32 bytes;
2. adicionar o Worker e o segredo na Cloudflare;
3. criar Routes para `paxincpa.store/api/*` e
   `www.paxincpa.store/api/*` sobre registros DNS Proxied;
4. testar as APIs ainda sem ativar a validação na Vercel;
5. adicionar o mesmo valor como `PAXINBOT_ORIGIN_GATE_SECRET`, Sensitive e
   somente Production na Vercel;
6. implantar e confirmar domínio oficial funcionando;
7. confirmar que uma chamada direta à origem retorna `404`.

Ativar a variável na Vercel antes do Worker interrompe todas as APIs. O rollback
é remover `PAXINBOT_ORIGIN_GATE_SECRET` da Vercel e reimplantar a última revisão.

## Limite da proteção

A barreira protege APIs, credenciais e operações. Arquivos públicos do site
continuam públicos mesmo quando acessados por outra origem, o que é esperado.
Ela não substitui WAF, rate limiting, autenticação, RLS nem validação de webhook.
