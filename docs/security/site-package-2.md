# Segurança do site — pacote 2

Este pacote endurece a fronteira HTTP entre o navegador, a Vercel e as funções
do Paxinbot. Ele não altera preços, acessos, migrações do Supabase ou regras de
pagamento.

## Implementado

- corpos JSON e `application/x-www-form-urlencoded` limitados a 32 KiB;
- respostas `400`, `413` e `415` explícitas para JSON inválido, excesso de
  tamanho e formato não aceito;
- CSRF por token *double submit*, cookie `SameSite=Strict`, validação em tempo
  constante e exigência de `Origin` ou `Referer` do próprio site;
- CSRF aplicado ao login, conta, checkout, painel owner e autorização de
  dispositivo feita pelo navegador;
- cabeçalhos globais `nosniff`, `DENY`, política de referenciador e política de
  permissões;
- CSP em modo `Report-Only`, sem permitir JavaScript inline;
- SDK do Supabase fixado no repositório, sem download de CDN durante o uso;
- callbacks de autenticação movidos de scripts inline para arquivos locais;
- testes negativos e teste do SHA-256 da dependência vendorizada.

## Deliberadamente adiado

- promover a CSP de observação para bloqueio;
- HSTS e regras WAF/rate limiting da Cloudflare;
- publicação na Vercel e promoção da branch de teste.

Esses itens pertencem aos próximos pacotes para que sejam testados sem alterar
a implantação pública antes da conclusão do plano inteiro.
