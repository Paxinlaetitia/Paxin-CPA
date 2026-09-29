# Cash Hunters: implantação de licenças

O site e o painel existentes continuam canônicos. O novo namespace não altera entitlements ou sessões do PAXINBOT. O cliente é o projeto vizinho `CASH HUNTERS - RECUPERACAO`, versão candidata 1.6.0. O instalador anterior 1.5.7 não exige licença e não é revogado retroativamente.

## Preparação e ordem

1. Executar os testes do site e os testes de banco/cliente/pacote. Confirmar backup recuperável do banco antes de migrar produção. Testes usam exclusivamente dados sintéticos; não usar clientes reais.
2. Aplicar `supabase/migrations/20260929_cpa_licenses.sql` depois das migrações existentes do site. Ela reutiliza `auth.users`, `paxinbot_is_owner` e a infraestrutura de rate limit; tabelas cpa têm RLS e RPCs com papéis restritos. Confirmar que anon e usuários comuns não podem ler tabelas nem executar RPCs privilegiados.
   Antes, executar `docs/cpa-licensing-preflight.sql`; depois, executar `docs/cpa-licensing-postcheck.sql`. Os dois consultam somente metadados e não leem linhas de clientes.
3. Gerar chaves uma única vez com `node scripts/cpa-generate-config.cjs DIRETORIO-PRIVADO-FORA-DO-REPOSITORIO cash-hunters-1.6.0-IDENTIFICADOR-UNICO`. O comando não imprime segredos e não sobrescreve arquivos. No Windows, limitar ACL da pasta ao administrador do software. Guardar backup cifrado; não enviar os arquivos privados por chat, Git ou OneDrive compartilhado.
4. Importar as quatro variáveis de `cpa-server-secrets.json` como secrets da Vercel Production. Manter a configuração Supabase e de sessão do site existente. Jamais adicionar esses valores à configuração pública, navegador ou instalador.
5. Compilar o cliente com `build.py cpa-public-config.json`. O build gera `private/server-release-key.json`. Incorporar esse mapa ao secret servidor `CPA_RELEASE_KEYS` **preservando outras releases autorizadas**. Ele contém chaves de conteúdo, não deve ir para o cliente/site público. Não reutilizar release IDs para outra chave.
6. Publicar os handlers e dependências do site usando o fluxo de deployment existente. Conferir `/api/licenses` e `/api/licenses-admin` no domínio HTTPS, cookies/CSRF e owner. A URL administrativa é preservada por rewrite e executa na mesma Vercel Function de `/api/licenses`, mantendo o projeto dentro do limite de funções. O painel fica na rota administrativa já existente, na aba Licenças Cash Hunters. Gerar uma licença sintética, validar ativação/renovação/revogação e removê-la de uso pelo painel.
   As rotas Cloudflare existentes cobrem `paxincpa.store/api/*` e `www.paxincpa.store/api/*`; o Worker encaminha as duas rotas de licença para a Vercel com o header de origem servidor a servidor. Não existe segredo adicional no cliente para essa passagem.
7. Validar o pacote de produção e instalação nativa; salvar recibo `validation/deployment.json` com `passed:true`, `build` igual ao diretório do build, `version` igual à versão do pacote e `manifestSha256` igual ao SHA-256 do manifesto final (`Cash Hunters <versão>/_internal/manifest.json`). Esses campos só devem ser preenchidos após verificação real do servidor e provisionamento da mesma release. `export_delivery.py` também exige exatamente os 14 cenários esperados sem duplicatas, os dois executáveis nativos aprovados com janela no mesmo processo, auditoria e instalador aprovados, além do hash do instalador ligado ao build atual. Ele recusa builds de teste e recibos ausentes ou desalinhados. Não usar esse arquivo para contornar uma verificação pendente.

## Administração

A chave completa é mostrada uma vez. O banco guarda HMAC versionado, identificador e prefixo. O painel usa o login de proprietário existente, sem cadastro administrativo separado. Duração usa horas/dias/semanas/meses de calendário UTC, data absoluta ou vitalício; primeira ativação começa no primeiro vínculo válido. Desativar, suspender, revogar e banir têm efeito servidor e invalidam sessões. Reset libera o vínculo; substituir associa explicitamente HWID e chave pública novos. Nunca pedir identificadores brutos de hardware.

Cliente faz renovação periódica; novas ações exigem autorização online. Queda de rede não cria autorização nova e não amplia o prazo já concedido. Sessão expirada ou negada encerra a execução local, com prazo curto de fechamento. O relógio local não aumenta validade. Cada processo tem sessão própria; identidade e licença salvas por DPAPI são comuns aos perfis do mesmo usuário Windows.

## Rotação e operação

HMAC: incluir uma nova versão em `CPA_LICENSE_HMAC_PEPPERS` e mudar `CPA_LICENSE_HMAC_CURRENT_VERSION`. Manter as anteriores enquanto houver licenças correspondentes. Assinatura: distribuir public key nova em build confiável antes de mudar `CPA_LICENSE_SIGNING_CURRENT_KID`; manter mapa de private keys só no servidor. Não aceitar chaves públicas fornecidas pelo cliente como autoridade do servidor. Retirar release de `CPA_RELEASE_KEYS` impede novas autorizações daquela release.

Monitorar erros por categoria, latência e rate limits sem registrar licenças, tokens ou chaves. Backups do banco devem ser cifrados e testados. Eventos administrativos e autenticações ficam na auditoria restrita. Administrador pode encerrar sessões; reset/revogação é verificado novamente no servidor.

A manutenção oportunista remove desafios 24 horas depois da expiração, sessões 30 dias depois da expiração e eventos de auditoria após 365 dias, em lotes limitados. Ajustar esses prazos exige uma nova migração revisada; não apagar registros manualmente durante uma investigação.

## Limites

HWID é uma identificação declarada pelo cliente, não atestação de hardware. DPAPI reduz cópia casual; quem controla o usuário/máquina pode estudar o programa e capturar material autorizado em memória. A autoridade para criar licenças, mudar vínculos e assinar respostas permanece servidor. Motor recuperado continua local; não alegar migração integral para SaaS, nem resistência absoluta a engenharia reversa. Homomorfismo e enclaves não resolvem o acesso ao DOM local e não foram introduzidos. Assinatura interna do manifesto não substitui Authenticode.
