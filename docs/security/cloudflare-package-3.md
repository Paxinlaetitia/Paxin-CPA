# Cloudflare — pacote 3 contra abuso

O roteiro cumulativo e a ordem de ativação agora ficam em
`docs/security/cloudflare-activation-guide.md`.

Este arquivo prepara a configuração de borda. As regras **não devem ser
ativadas** antes de todos os pacotes estarem prontos e a implantação de teste
ter sido validada.

## Camadas previstas

1. Manter o DNS de `paxincpa.store` e `www.paxincpa.store` com proxy ativo.
2. Confirmar que o Cloudflare Free Managed Ruleset permanece ativo. A
   Cloudflare informa que esse subconjunto é implantado por padrão no plano
   Free.
3. Usar a única regra de rate limiting do plano Free para absorver rajadas nos
   endpoints de autenticação. Os limites longos e por conta continuam sendo
   aplicados pela Vercel e pelo Supabase.
4. Revisar Security Analytics e Security Events antes de aumentar a
   agressividade de qualquer bloqueio.

## Regra de rate limiting compatível com o plano Free

- Nome: `Paxinbot - rajadas de autenticacao`
- Expressão: `starts_with(http.request.uri.path, "/api/auth/")`
- Característica: endereço IP
- Período: `10 segundos`
- Requisições por período: `20`
- Ação: `Block`
- Mitigation timeout: `10 segundos`

O plano Free permite uma regra, contagem por IP e período de 10 segundos. Esse
limite de borda não substitui os contadores distribuídos do aplicativo: a
Cloudflare documenta que pode haver alguns segundos de atraso até a mitigação
entrar em vigor.

Não usar `Managed Challenge` em `/api/v1/`, porque esses endpoints são chamados
pelo aplicativo Electron e esperam JSON. Não criar uma regra global de
allowlist para o Mercado Pago: a assinatura do webhook continua sendo validada
na origem e uma liberação global poderia ignorar outras proteções do WAF.

## Referências oficiais

- https://developers.cloudflare.com/waf/rate-limiting-rules/
- https://developers.cloudflare.com/waf/get-started/
- https://developers.cloudflare.com/waf/tools/ip-access-rules/
