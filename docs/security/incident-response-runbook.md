# Runbook de resposta a incidentes do Paxinbot

Este documento é operacional. Ele registra ações e nomes de variáveis, nunca os
valores. O owner é o comandante do incidente enquanto não existir outra pessoa
formalmente designada.

## Classificação

| Nível | Exemplo | Início da resposta |
| --- | --- | --- |
| SEV1 | vazamento confirmado, acesso indevido ao banco, pagamentos liberados incorretamente | imediato |
| SEV2 | login ou checkout amplamente indisponível, ataque ativo contido parcialmente | até 30 minutos |
| SEV3 | falha limitada, abuso sem acesso a dados, fornecedor degradado | até 2 horas |
| SEV4 | alerta sem impacto ou problema cosmético | próximo período de trabalho |

## Primeiros 15 minutos

1. registrar horário, sintomas e identificadores de requisição;
2. não copiar cookies, tokens, chaves, e-mails completos ou payloads de pagamento;
3. confirmar se o incidente afeta produção, preview ou somente um fornecedor;
4. abrir os eventos da Cloudflare, logs da Vercel, Security Advisor do Supabase
   e auditoria do Paxinbot usando a menor janela de tempo necessária;
5. identificar a última implantação conhecida como íntegra;
6. classificar a gravidade e escolher uma única pessoa para executar mudanças;
7. preservar evidências redigidas antes de revogar ou substituir credenciais.

## Contenção

### Segredo ou conta administrativa comprometida

1. encerrar sessões do provedor e trocar a senha da conta afetada;
2. confirmar MFA e remover dispositivos ou métodos desconhecidos;
3. revogar primeiro a credencial no provedor;
4. criar uma credencial nova, restrita à mesma finalidade;
5. atualizar somente o ambiente correto da Vercel ou Worker;
6. reimplantar a última revisão íntegra e testar o fluxo mínimo;
7. nunca manter o valor comprometido em logs, tickets ou anotações.

### Implantação ou cadeia de build comprometida

1. desabilitar temporariamente deployments automáticos da Vercel;
2. revogar tokens GitHub/Vercel suspeitos e revisar aplicações instaladas;
3. restaurar a implantação de um commit conhecido e assinado pelo histórico;
4. revisar alterações em workflows, `vercel.json`, `api/` e migrações;
5. só reabrir merges depois de `Security CI` passar novamente.

### Abuso, DDoS ou credenciais automatizadas

1. confirmar a rota e o padrão em Security Events;
2. aplicar bloqueio ou Managed Challenge estreito e com expiração;
3. manter webhooks e autorização do aplicativo fora de desafios interativos;
4. não bloquear faixas extensas com base em um único IP;
5. acompanhar respostas `429`, erros legítimos e falsos positivos.

### Banco ou autorização indevida

1. suspender o fluxo que escreve os dados afetados;
2. revogar a chave secreta do Supabase se houver suspeita de exposição;
3. revisar RLS, grants e funções `SECURITY DEFINER` antes de restaurar acesso;
4. não apagar registros de auditoria durante a investigação;
5. corrigir por uma nova migração; não editar silenciosamente uma migração já
   aplicada.

## Rotação de segredos

| Segredo | Efeito esperado | Verificação |
| --- | --- | --- |
| `SUPABASE_SECRET_KEY` | backend privilegiado para até revogar/substituir | login, owner, dispositivo e webhook |
| `PAXINBOT_SESSION_SECRET` | invalida sessões web e altera pseudônimos derivados; usar apenas quando necessário | novo login, dispositivos e bloqueios |
| `MERCADOPAGO_ACCESS_TOKEN` | pagamentos indisponíveis durante a troca | PIX sandbox e consulta de pagamento |
| `MERCADOPAGO_WEBHOOK_SECRET` | assinaturas antigas deixam de validar | evento de teste assinado |
| `RESEND_API_KEY` | envio de e-mail interrompido durante a troca | e-mail transacional de teste |
| `PAXINBOT_ORIGIN_GATE_SECRET` | API aceita somente tráfego marcado pelo Worker | domínio oficial funciona e origem direta falha |
| chaves de módulos protegidos | release anterior pode precisar ser retirado | autorização e download do release vigente |

Para o segredo do webhook e da origem existe sobreposição opcional de no máximo
48 horas. Configure o valor novo como atual, o antigo como `PREVIOUS` e uma data
ISO em `PREVIOUS_UNTIL`. Depois da troca do fornecedor/Worker, remova as duas
variáveis anteriores. Não use a sobreposição para um segredo confirmado como
vazado: revogue-o imediatamente.

## Recuperação

1. fazer rollback na Vercel para o commit íntegro quando o defeito for somente
   de código;
2. para banco, criar migração corretiva e obter um backup lógico antes de
   mudanças destrutivas;
3. validar restauração do backup em ambiente isolado antes de depender dele;
4. conferir contagem de usuários, produtos, acessos, pedidos e auditoria sem
   exportar dados pessoais para arquivos locais;
5. executar login, código por e-mail, passkey, painel owner, PIX/cartão, webhook,
   autorização e revogação do aplicativo;
6. manter monitoramento reforçado por pelo menos 24 horas;
7. reativar deployments automáticos somente após a verificação.

Recursos de backup e retenção variam conforme o plano do Supabase. Confirme no
painel o que está realmente habilitado; a existência de uma opção na interface
não prova que uma restauração foi testada.

## Comunicação

Atualização inicial: “Estamos investigando uma indisponibilidade em [função]. O
acesso a dados não está confirmado como afetado. Próxima atualização em [hora].”

Resolução: “O serviço foi restaurado às [hora]. A causa foi contida e os fluxos
críticos foram validados. Quando aplicável, clientes afetados receberão
orientações privadas.”

Não atribua causa antes da confirmação. Não publique IPs, e-mails, identificadores
de dispositivos, segredos ou detalhes que facilitem exploração.

## Pós-incidente

Em até cinco dias úteis:

1. construir uma linha do tempo em UTC e horário de Brasília;
2. registrar causa raiz e fatores contribuintes sem culpar pessoas;
3. listar dados e clientes realmente afetados;
4. registrar controles que falharam e os que limitaram o impacto;
5. criar correções com responsável e prazo;
6. atualizar este runbook e executar um teste de recuperação;
7. revisar obrigações legais e de comunicação com apoio profissional quando
   houver possível exposição de dados pessoais.
