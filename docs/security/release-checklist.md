# Gate de liberação do Paxinbot

**Estado atual: NÃO APROVADO PARA PRODUÇÃO.**

O código somente pode sair de `staging` depois que a auditoria local e todos os
gates externos abaixo estiverem aprovados para o mesmo commit. Um teste local
não comprova o funcionamento da Vercel, Supabase, Cloudflare, Mercado Pago,
Resend ou do instalador do aplicativo.

## 1. Código e cadeia de build

- `node scripts/security-ci.js` aprovado;
- `node --test tests/*.test.js` aprovado;
- `node scripts/release-audit.js --mode local` aprovado;
- Security CI aprovado no GitHub para o commit exato;
- branch `staging` protegida contra force push e merge sem status;
- nenhuma credencial ou arquivo `.env` rastreado;
- revisão humana do diff entre o último release e o candidato.

## 2. Supabase de teste

- todas as migrações, até `20260831_database_least_privilege.sql`, aplicadas;
- Security Advisor revisado e nenhum alerta crítico ignorado;
- RLS e grants confirmados para usuário anônimo, autenticado e backend;
- cadastro, confirmação de e-mail, login, recuperação, Google e passkey testados;
- SMTP e URLs de redirecionamento limitados aos domínios previstos;
- owner confirmado somente pelo fluxo autorizado, sem flag administrativa no cliente;
- criação, pausa, consumo e revogação de acesso testados;
- backup disponível e restauração ensaiada no ambiente de teste.

## 3. Vercel Preview

- variáveis separadas entre Preview e Production;
- segredos marcados como Sensitive e ausentes dos logs/build;
- domínio de preview não indexado e sem cache de respostas privadas;
- cadastro, painel, administração, checkout, webhook e autorização desktop testados;
- respostas de erro não revelam stack, tabelas, tokens ou dados pessoais;
- orçamento Hobby preservado e funções dentro do limite automatizado.

## 4. Cloudflare

- DNS oficial como Proxied e SSL/TLS em Full (strict);
- HTTPS forçado e HSTS ativado somente após validação completa;
- WAF gerenciado e regras de rate limiting sem falso positivo crítico;
- nenhuma rota `/api/*` armazenada em cache;
- Worker de origem publicado nas duas Routes oficiais;
- segredo do Worker armazenado como Secret e correspondente ao da Vercel;
- origem direta bloqueada, domínio oficial funcionando e rollback ensaiado;
- Security Events e alertas de DDoS configurados.

As ações exatas e o registro por etapa ficam em
`cloudflare-activation-guide.md`.

## 5. Pagamentos e e-mail

- credenciais sandbox e live separadas;
- PIX, cartão, aprovação, recusa, expiração e repetição testados em sandbox;
- webhook aceita POST, valida autenticidade e é idempotente;
- valor e produto sempre recuperados pelo backend, nunca confiados ao navegador;
- domínio do remetente verificado e SPF/DKIM/DMARC conferidos;
- confirmação, recuperação e aviso transacional entregues sem expor segredo.

## 6. Aplicativo e distribuição

- versão, ícone, instalador e URL de download correspondem ao release;
- hash/assinatura do artefato conferidos pelo fluxo de integridade;
- autorização via navegador não envia senha ao executável;
- revogação de dispositivo encerra a sessão conforme o contrato;
- contador de uso, pausa, expiração, banimento e atualização testados;
- pacote publicado não contém configuração local, licença de teste ou logs sensíveis;
- rollback para o instalador anterior está disponível.

## 7. Evidência e aprovação

Copie `release-evidence.example.json` para `release-evidence.local.json`, sem
remover o arquivo do `.gitignore`. Para cada gate, marque `passed: true` e
registre somente uma referência curta, por exemplo o número do teste, horário
ou URL interna sem token. O arquivo não pode conter chaves ou dados pessoais.

Depois, no mesmo commit e em árvore limpa:

```powershell
node scripts/release-audit.js --mode release --evidence release-evidence.local.json
```

A evidência expira em 72 horas. Alterar o commit invalida a aprovação. O comando
de liberação falha quando faltar qualquer gate.

## 8. Sequência de ativação

1. aprovar a auditoria local e o CI de `staging`;
2. aplicar migrações e testar Supabase/Preview;
3. validar pagamentos, e-mail e autorização do aplicativo;
4. ativar Cloudflare por etapas, deixando a barreira de origem por último;
5. preencher a evidência e aprovar a auditoria de liberação;
6. somente então promover o mesmo commit para produção;
7. observar erros, latência, bloqueios e pagamentos por 48 horas;
8. em regressão crítica, reverter Vercel, remover o gate de origem se necessário
   e seguir `incident-response-runbook.md`.
