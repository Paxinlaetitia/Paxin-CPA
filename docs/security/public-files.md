# Arquivos publicos do site

## Publicacao verificada em 2026-09-04

- Hotfix publicado: `dpl_G2ki8L8MQyxatRNy5oKd1L9e9FmG`.
- Implantacao anterior preservada: `dpl_Ejv6dFTArWcDQcP5Q2PFDJrexSJf`.
- Base confirmada na API da Vercel: commit
  `9fefd8f3d6bcf2719b61e1e4fd72e91aa2662aff`, o mesmo que estava em producao.
- Publicacao isolada: somente build-public.cjs, configuracao de output e ignores;
  sem as mudancas pendentes do atualizador nem SQL de permissoes.
- 118 testes passaram na copia isolada; 125 no workspace completo.
- No dominio www, os nove caminhos privados da verificacao retornaram 404;
  conta e catalogo responderam 200, auth/me respondeu 401 sem sessao e a API de
  modulos respondeu 405 para GET, sem erro de modulo ausente.
- 28 arquivos publicos corresponderam diretamente aos fontes. A pagina inicial
  correspondeu apos excluir apenas o script de challenge injetado pela Cloudflare.
  O manifesto de release respondeu 200 na origem Vercel; o 404 desse caminho no
  dominio e previsto pelo Worker existente, que filtra os caminhos /releases/.
- Verificacoes de login autenticado, pagamento real e operacao desktop nao foram
  executadas nesta correcao. As funcoes de negocio nao foram alteradas.
- Os ajustes locais de configuracao devem acompanhar o proximo commit/deploy
  pelo Git para que uma publicacao futura nao reintroduza a raiz publica.

JavaScript de interface e CSS precisam ser baixados pelo navegador e permanecem
visiveis no DevTools. Minificacao, troca de extensao ou bloqueio do DevTools nao
transformam esses arquivos em segredos. Login, autorizacao, validacao de pagamentos
e chaves privadas devem continuar protegidos no servidor.

Na verificacao anterior a esta correcao, as URLs
`/server/protected-release-crypto.js` e `/server/security-log.js` responderam HTTP
200 com os mesmos arquivos do codigo local. Nao foram encontrados nesses dois
arquivos os padroes de credenciais literais procurados; isso nao e uma auditoria
completa de segredos. `.env`, a migracao SQL verificada, o teste verificado e o
asset interno de admin verificado responderam 404.

## Correcao

`node build-public.cjs` gera `public-site` usando uma lista EXPLICITA de arquivos.
`vercel.json` publica somente essa pasta como conteudo estatico. Os fontes de
`server/` continuam no projeto para empacotamento das funcoes em `api/`, sem serem
copiados para a saida publica. Nao adicionar `server/` ao `.vercelignore`, pois isso
pode impedir o empacotamento de dependencias das APIs.

A lista permite apenas paginas e assets atuais, incluindo o manifesto publico de
release. Nao inclui configuracoes, testes, SQL, documentos internos, backups,
source maps, fontes do servidor ou arquivos de build. Novos assets exigem revisao
e inclusao explicita. Os arquivos frontend existentes nao foram removidos nem
modificados. O codigo so le variaveis de ambiente em runtime das APIs; o build nao
injeta segredos no frontend.

## Validacao apos publicar

Em uma implantacao isolada que contenha esta correcao, conferir:

- `/`, `/conta`, login e catalogo funcionam; os JS/CSS publicos continuam com 200.
- `/server/protected-release-crypto.js`, `/server/security-log.js`,
  `/server/update-manifest.js`, `/vercel.json`, `/build-public.cjs` e arquivos
  `.env`, de testes, SQL e backups retornam 404, nunca codigo-fonte.
- APIs continuam executando e o painel admin continua condicionado a sessao owner.
- Conferir o dominio final, inclusive comportamento de caches. Nao declarar a
  exposicao resolvida em producao apenas porque o build local passou.

Referencias:
- https://vercel.com/docs/project-configuration/vercel-json#outputdirectory
- https://developer.mozilla.org/en-US/docs/Learn_web_development/Extensions/Server-side/First_steps/Client-Server_overview
