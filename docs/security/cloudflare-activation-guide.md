# Guia cumulativo de ativação da Cloudflare

Este é o roteiro operacional único do Paxinbot. Ele deve ser atualizado a cada
novo pacote. **Nenhuma etapa abaixo foi ativada por estes commits.** Execute em
produção somente depois que todos os pacotes e o preview estiverem aprovados.

## Estado dos pacotes

| Pacote | Proteção preparada | Ativação na Cloudflare |
| --- | --- | --- |
| 1 | segredos separados por ambiente | nenhuma regra; confirmar MFA da conta |
| 2 | CSRF, limites de corpo e cabeçalhos | manter proxy e HTTPS; ainda sem HSTS |
| 3 | rate limit distribuído | uma regra de rajada em `/api/auth/` |
| 4 | CSP bloqueante, host oficial e cache privado | SSL estrito, cache bypass, WAF e HSTS gradual |
| 5 | correlação, auditoria sanitizada e retenção limitada | alerta HTTP DDoS por e-mail e rotina de revisão |
| 6 | RLS, grants opt-in e RPCs mínimos no Supabase | nenhuma regra nova; revisar DNS e segredos de origem |
| 7 | CI somente leitura, actions imutáveis e verificação de supply chain | nenhuma regra nova; proteger `staging` e `main` no GitHub |
| 8 | porta de origem, rotação e recuperação | Worker em `/api/*`, Secret binding e runbook; ativar somente após o Pacote 9 |
| 9 | auditoria integrada e gate de liberação fail-closed | executar Etapa 11 e `release-checklist.md`; produção continua pendente |

## Etapa 0 — pré-requisitos

- confirmar que `paxincpa.store` e `www.paxincpa.store` apontam para a Vercel;
- manter ambos os registros web como **Proxied**;
- confirmar que nenhum registro de e-mail usado por Resend está com proxy;
- manter acesso por MFA na Cloudflare e guardar códigos de recuperação offline;
- validar todo o preview antes de alterar a zona de produção.

## Etapa 1 — TLS e redirecionamento

Em **SSL/TLS**:

1. selecionar `Full (strict)`;
2. ativar `Always Use HTTPS`;
3. definir `Minimum TLS Version` como `TLS 1.2`;
4. manter `TLS 1.3` ativo;
5. não ativar HSTS ainda.

Validar página pública, área do cliente, Google OAuth, webhook e aplicativo por
24 horas. `Flexible` não deve ser usado.

## Etapa 2 — cache seguro

Criar uma Cache Rule chamada `Paxinbot - dados privados` com a ação
`Bypass cache` e a expressão:

```text
starts_with(http.request.uri.path, "/api/") or
starts_with(http.request.uri.path, "/conta") or
starts_with(http.request.uri.path, "/gestao/") or
http.request.uri.path in {"/activate" "/auth-callback" "/redefinir-senha"}
```

Não criar `Cache Everything` para HTML. CSS, JavaScript, SVG e imagens podem
continuar usando o cache padrão da Cloudflare.

## Etapa 3 — WAF básico

- confirmar que o `Cloudflare Free Managed Ruleset` está ativo;
- observar **Security > Events** antes de criar exceções;
- nunca criar allowlist global para Mercado Pago, Supabase ou Vercel;
- se houver falso positivo, limitar a exceção ao caminho e controle exatos.

Regra customizada recomendada, ação `Block`:

```text
http.request.method in {"TRACE" "CONNECT"}
```

## Etapa 4 — rate limiting do Pacote 3

Criar a única regra do plano Free:

- nome: `Paxinbot - rajadas de autenticacao`;
- expressão: `starts_with(http.request.uri.path, "/api/auth/")`;
- característica: IP;
- limite: 20 requisições em 10 segundos;
- ação: `Block`;
- duração da mitigação: 10 segundos.

Os limites longos continuam no Supabase. Não aplicar desafio às rotas
`/api/v1/`, pois o aplicativo espera respostas JSON.

## Etapa 5 — bots

Manter `Bot Fight Mode` **desativado inicialmente**. No plano Free ele age no
domínio inteiro e não aceita exceções. Só ativar após confirmar em ambiente
controlado que webhook do Mercado Pago, autorização do aplicativo e Google
OAuth continuam funcionando. Se qualquer cliente automatizado legítimo falhar,
desativá-lo e manter WAF mais rate limit.

## Etapa 6 — HSTS gradual

HSTS é a última alteração porque uma configuração incorreta pode tornar o
domínio inacessível pelo período escolhido.

1. após sete dias estáveis em HTTPS, ativar HSTS com `Max Age: 1 month`,
   `includeSubDomains: Off` e `Preload: Off`;
2. após mais 30 dias sem falhas, elevar para `6 months`;
3. usar `12 months` e `includeSubDomains` somente quando **todos** os subdomínios
   atuais e futuros estiverem permanentemente em HTTPS;
4. considerar `Preload` apenas como decisão final e separada.

Não pausar a Cloudflare, trocar nameservers ou remover HTTPS enquanto uma
política HSTS ainda estiver válida.

## Etapa 7 — monitoramento do Pacote 5

No plano Free, não procurar por `Security Events Alert`: esse alerta de pico de
WAF está disponível somente no Business e Enterprise. Usar os recursos abaixo:

1. em **Notifications > Add**, criar `Paxinbot - HTTP DDoS`;
2. selecionar `HTTP DDoS Attack Alert` e entrega por e-mail;
3. usar o e-mail protegido do proprietário e confirmar o recebimento;
4. em **Security > Events**, revisar diariamente os eventos amostrados das
   últimas 24 horas durante a fase de lançamento;
5. em **Security Analytics**, revisar a tendência de sete dias em janelas de
   consulta de no máximo 24 horas;
6. comparar os horários de bloqueio com a aba **Auditoria** do painel Paxinbot,
   sem copiar IPs ou credenciais para chamados;
7. nos logs da Vercel, procurar por `site_security_event.delivery_failed`. Esse
   diagnóstico indica migração ausente ou indisponibilidade do Supabase e não
   contém o evento sensível original.

Não configurar webhook de notificações: no Cloudflare Free a entrega garantida
é por e-mail. Não criar regras adicionais em resposta a um único evento
amostrado; primeiro confirmar repetição, rota e impacto legítimo.

## Etapa 8 — banco e origem do Pacote 6

O WAF da Cloudflare protege `paxincpa.store`, mas não substitui RLS ou grants no
domínio externo do Supabase. Não há nova regra de Cloudflare para ativar neste
pacote. Faça apenas esta revisão:

1. em **DNS > Records**, confirmar que não existe registro `db`, `postgres`,
   `pooler` ou `supabase` apontando diretamente para o banco;
2. manter somente os hosts web da Vercel como **Proxied**;
3. manter registros SMTP/DKIM/SPF/DMARC do Resend como **DNS only**;
4. não copiar `SUPABASE_SECRET_KEY`, senha do banco ou connection string para
   regras, snippets, Zaraz, Workers ou código entregue ao navegador;
5. aceitar no navegador somente a chave `sb_publishable_`, que continua
   dependente de RLS e grants mínimos;
6. depois da migração de teste, executar o Security Advisor do Supabase e
   revisar individualmente qualquer função `SECURITY DEFINER` exposta. Somente
   os RPCs enumerados no Pacote 6 são esperados.

## Etapa 9 — cadeia de build do Pacote 7

Não há configuração equivalente no painel da Cloudflare. Depois do primeiro
push de teste:

1. confirmar no GitHub Actions que `Security CI` passou em `staging`;
2. no ruleset de `staging`, exigir o status
   `Validate source and security boundaries`;
3. repetir a exigência em `main` somente após o preview ser aprovado;
4. manter o projeto Vercel conectado apenas ao repositório oficial;
5. não adicionar tokens da Cloudflare, Supabase ou Mercado Pago ao workflow.

## Etapa 10 — porta de origem do Pacote 8

Não executar antes do Pacote 9. Quando o preview estiver aprovado:

1. em **Workers & Pages**, criar o Worker `paxinbot-origin-gate` com o arquivo
   `cloudflare/origin-gate-worker.mjs`;
2. em **Settings > Variables and Secrets**, adicionar
   `PAXINBOT_ORIGIN_GATE_SECRET` como **Secret**, nunca como texto aberto;
3. adicionar `PAXINBOT_DOWNLOAD_SIGNING_SECRET` como **Secret** e usar o mesmo
   valor na Vercel Production;
4. em **Settings > Bindings**, adicionar um binding R2 chamado
   `PAXINBOT_RELEASES` apontando para o bucket privado `paxinbot-releases`;
5. em **Settings > Domains & Routes**, adicionar as Routes
   `paxincpa.store/api/*`, `www.paxincpa.store/api/*`,
   `paxincpa.store/releases/*` e `www.paxincpa.store/releases/*`;
6. confirmar antes que os dois registros DNS estão como **Proxied**;
7. testar login, catálogo e um webhook ainda sem configurar o segredo na Vercel;
8. somente então adicionar o mesmo segredo de origem na Vercel como Sensitive, escopo
   Production, e reimplantar;
9. confirmar que o domínio oficial funciona, que a origem direta não alcança
   as APIs;
10. entrar na Área do Cliente, gerar um download e confirmar que o Worker
    responde com `Content-Disposition: attachment` e não expõe `r2.dev`;
11. se houver falha, remover a variável da Vercel e fazer rollback do deployment.

Na rotação, primeiro implante na Vercel o segredo novo como atual e o antigo em
`PAXINBOT_ORIGIN_GATE_PREVIOUS_SECRET`, com prazo de até 48 horas. Depois troque
o Secret do Worker. Ao final, remova as variáveis anteriores.

## Etapa 11 — verificação final

- executar `node scripts/release-audit.js --mode local` e confirmar que o código
  passou enquanto os gates externos continuam pendentes;
- executar login, cadastro, recuperação, checkout e autorização do aplicativo;
- confirmar respostas `429` em rajadas e funcionamento normal abaixo do limite;
- verificar `CF-Cache-Status` como não armazenado nas rotas privadas;
- revisar Security Events por falsos positivos durante 48 horas;
- registrar data, responsável e resultado de cada etapa neste documento;
- preencher a evidência local conforme `release-checklist.md` e executar a
  auditoria de liberação para o mesmo commit. Sem essa aprovação, não promover.

## Registro de ativação

| Etapa | Data | Responsável | Resultado / rollback |
| --- | --- | --- | --- |
| 0 | pendente | — | — |
| 1 | pendente | — | — |
| 2 | pendente | — | — |
| 3 | pendente | — | — |
| 4 | pendente | — | — |
| 5 | opcional | — | — |
| 6 | pendente | — | — |
| 7 | pendente | — | — |
| 8 | revisão | — | — |
| 9 | GitHub | — | — |
| 10 | Cloudflare + Vercel | — | — |
| 11 | gate final pendente | — | — |

## Referências oficiais

- https://developers.cloudflare.com/ssl/edge-certificates/additional-options/http-strict-transport-security/
- https://developers.cloudflare.com/waf/get-started/
- https://developers.cloudflare.com/waf/rate-limiting-rules/
- https://developers.cloudflare.com/waf/feature-interoperability/
- https://developers.cloudflare.com/cache/how-to/cache-rules/settings/
- https://developers.cloudflare.com/notifications/
- https://developers.cloudflare.com/ddos-protection/reference/alerts/
- https://developers.cloudflare.com/waf/analytics/security-events/
- https://developers.cloudflare.com/waf/analytics/security-analytics/
- https://developers.cloudflare.com/workers/configuration/routing/routes/
- https://developers.cloudflare.com/workers/configuration/secrets/
