# Segurança do site — pacote 7 de 9

O Pacote 7 protege a cadeia entre uma alteração no GitHub e o build enviado à
Vercel. Ele não publica o site e não adiciona dependências ao produto.

## Implementado

- workflow para `main`, `staging` e pull requests;
- token do GitHub limitado a leitura;
- checkout sem credencial persistente;
- actions oficiais fixadas por SHA completo e imutável;
- verificação de sintaxe e suíte de regressão no Node.js 22;
- bloqueio de arquivos `.env`, credenciais conhecidas e chaves privadas
  rastreadas pelo Git;
- limite automático de 12 funções da Vercel Hobby;
- manifesto de pacote futuro obrigado a possuir lockfile;
- instalação npm futura com scripts de ciclo de vida desativados e auditoria de
  vulnerabilidades altas ou críticas;
- Dependabot semanal somente para GitHub Actions;
- ownership explícito dos arquivos sensíveis.

O inventário atual encontrou zero pacotes npm diretos ou transitivos. Portanto,
não há CVEs ou licenças de bibliotecas npm para avaliar neste momento. As duas
dependências operacionais do CI são `actions/checkout` e `actions/setup-node`,
ambas oficiais e fixadas em commits completos.

A revisão de ataque do workflow não encontrou caminho explorável por um usuário
externo: pull requests não recebem segredos, o token é somente leitura, nenhuma
expressão controlada pelo autor é executada no shell e não há runner próprio.

## Ativação no GitHub depois do primeiro push de teste

Em **Settings > Branches** ou **Rules > Rulesets**, proteger `main`:

1. exigir pull request antes do merge;
2. exigir o status `Validate source and security boundaries`;
3. bloquear force push e exclusão da branch;
4. exigir resolução das conversas;
5. não exigir aprovação de CODEOWNER enquanto houver apenas um proprietário,
   porque o autor não pode aprovar a própria alteração.

Aplicar primeiro em `staging`. Somente repetir em `main` quando o workflow tiver
passado no preview.

## Cloudflare

Nenhuma regra nova precisa ser ativada neste pacote. Cloudflare não valida o
código-fonte do build; essa fronteira pertence ao GitHub e à Vercel. Continue
sem publicar produção até os Pacotes 8 e 9 terminarem.

## Pacotes restantes

- **Pacote 8:** resposta a incidentes, rotação de segredos, recuperação e
  controles finais de origem/Cloudflare;
- **Pacote 9:** auditoria integrada, checklist de lançamento e preparação do
  preview para aprovação.
