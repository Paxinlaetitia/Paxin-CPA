# Backup manual gratuito no Windows

## Executar

Baixe o certificado CA publico em Supabase > Database > Settings > SSL Configuration.
Guarde-o em `%LOCALAPPDATA%\PAXINBOT\BackupTools\supabase-ca.crt`, ou passe
`-RootCertificatePath` ao script PowerShell. O certificado deve ser uma CA dentro
da validade, sem chave privada. O script o adiciona apenas ao pacote de confianca
usado pelo backup, sem instalar certificados no Windows e mantendo `verify-full`.

Abra `Backup-Supabase.cmd` com duplo clique no Explorador de Arquivos. Ele localiza
PowerShell 7 nos locais padrao de instalacao ou no runtime local do Codex, sem
depender do PATH herdado pelo Explorador. Usa as ferramentas PostgreSQL 18.6 em
`%LOCALAPPDATA%\PAXINBOT\BackupTools\postgresql-18.6\bin`.
Nao instala servidor, nao altera configuracoes do Supabase e nao aplica migracoes.
As ferramentas e os backups sao localizados pela pasta LocalApplicationData
registrada pelo Windows, sem depender do valor LOCALAPPDATA herdado pelo terminal.
O caminho das ferramentas aparece antes da solicitacao de senha; se faltar um
executavel, a execucao normal prepara as ferramentas nesse mesmo Windows antes
de pedir qualquer credencial. Reutiliza o ZIP local somente se o SHA-256 confere;
se ausente, baixa aproximadamente 344 MB do endereco oficial EDB fixado no script.
Nao precisa de administrador e nao instala servidor PostgreSQL ou servicos.
Sao extraidos somente os quatro clientes e bibliotecas DLL, com verificacao de hash.
Arquivos existentes identicos sao preservados; divergentes fazem a preparacao parar
sem sobrescrita. Download parcial e preservado para inspecao em caso de falha.
Nao desative antivirus, TLS ou politicas do Windows se a preparacao falhar.
Ao terminar, o iniciador mantem a janela aberta ate pressionar uma tecla, inclusive
se PowerShell ou o script falharem antes de pedir a senha. Se houver erro, copie
apenas a mensagem/codigo visivel. O modo `--check` nao pausa.

O iniciador ja usa o **Host** e o **User** fornecidos pelo usuario para o projeto
`drkyjgnctbxmupbfarnj`: `aws-0-us-east-1.pooler.supabase.com` e
`postgres.drkyjgnctbxmupbfarnj`. Esses identificadores nao sao a senha.
Confira o projeto exibido na janela antes de continuar. A porta e fixa em 5432
(session mode, nao transaction mode). Executar o script sem esses parametros ainda
permite informa-los manualmente, conforme **Connect > Session pooler**.
A senha do banco sera pedida separadamente, com entrada
oculta. Nao e a senha de login do painel e nao deve ser enviada ao chat nem colada
em uma URL/comando. Nao redefina a senha automaticamente: isso pode afetar o app.

O destino e `%LOCALAPPDATA%\PAXINBOT\DatabaseBackups\<data-hora-id-unico>`.
Fica fora do OneDrive, Git, publicacao Vercel e dos backups de versao do aplicativo.
A pasta e criada com acesso somente para o usuario Windows atual e SYSTEM antes
de qualquer dado ser salvo. Administradores podem assumir controle dela; ACL nao
e criptografia. A copia continua sensivel: inclui usuarios, hashes e tokens do banco.
Nao envie arquivos dump/SQL ao chat e nao os publique. Proteja o disco e prepare
uma copia externa criptografada separadamente para tolerar perda deste computador.

## Resultado e verificacao

- `database.dump`: exportacao logica do banco em formato custom do pg_dump, com
  estrutura, dados e ACLs/proprietarios. Nao inclui arquivos dos buckets.
- `roles.sql`: papeis e associacoes sem senhas dos roles.
- `archive-contents.txt`: inventario do arquivo, para revisao local.
- `trusted-roots.pem`: certificados CA publicos do Windows e a CA explicitamente fornecida do Supabase.
- `BACKUP-MANIFEST.json`: so e criado apos as exportacoes, verificacao do inventario,
  leitura integral pelo pg_restore para NUL e calculo SHA-256. Contem a referencia
  do projeto e informa `restoreTested: false`.
- `INCOMPLETE.json`: se presente, houve falha. Preserve a pasta para inspecao,
  nao considere o backup concluido e nao aplique o corretivo do banco.

Para conferir a execucao, compartilhe somente o estado e a etapa indicados, ou o
manifesto (que nao inclui senha nem linhas de dados). Nunca compartilhe o dump.
Certificado invalido, falha de permissao, senha errada, timeout ou arquivo incompleto
interrompem o procedimento. Nao desative TLS nem amplie grants para contornar erros.

## Limites importantes

Este e um arquivo de preservacao via pg_dump bruto, nao um clone pronto do projeto.
Os schemas/roles gerenciados pelo Supabase exigem revisao seletiva antes da
restauracao; nao execute roles.sql ou pg_restore diretamente na producao.
Teste recuperacao em ambiente separado antes de depender dele para rollback.
O teste de leitura do arquivo NAO demonstra uma restauracao bem-sucedida.

O cliente 18.6 pode exportar servidores mais antigos suportados, mas seu SQL nao
tem restauracao garantida em uma versao anterior a 18. O manifesto registra a
versao real; prefira um cliente da mesma versao principal para um ensaio posterior
de restauracao em servidor antigo. Roles sao exportados em outra conexao, fora do
snapshot do dump; evite alteracoes de estrutura/permissoes durante a coleta.

Nao inclui objetos do Storage/R2, configuracoes do painel, funcoes Edge, variaveis
Vercel/Cloudflare, senhas dos roles nem chave-raiz do Vault. O backup do aplicativo
e outro processo, com regras diferentes e sem dados pessoais/segredos.

A senha fica temporariamente na memoria do processo filho (`PGPASSWORD`), nunca
na linha de comando, no historico ou em arquivo de credencial. Isso nao protege
contra administradores/malware capazes de inspecionar memoria/processos locais.
Todas as variaveis PG herdadas sao removidas do filho antes da configuracao explicita.

## Checagens locais sem conexao

`pwsh -NoProfile -File scripts/backup-supabase.ps1 -CheckOnly`

Sem PowerShell 7 no PATH, execute `Backup-Supabase.cmd --check` pelo CMD.
Esse modo testa o mesmo iniciador sem pedir senha nem conectar ao banco.
Ele nao baixa nem instala ferramentas. Para preparar somente as ferramentas, use
`Backup-Supabase.cmd --prepare`; essa opcao nunca solicita senha ou conecta ao banco.

`node --test tests/backup-supabase.test.js`

As checagens locais nao acessam credenciais reais nem o Supabase.

Ferramentas: ZIP Windows x64 indicado na pagina oficial EDB, baixado por HTTPS.
SHA-256 observado: `59F8CE701C63C2ED623C665A5E51B3EF6F2E37CCF837B68FFEED0742D0AE6ABD`.
Esse hash identifica o arquivo baixado; nao e uma assinatura independente do fornecedor.

Referencias:

- https://supabase.com/docs/guides/platform/backups
- https://supabase.com/docs/guides/platform/migrating-within-supabase/backup-restore
- https://supabase.com/docs/guides/self-hosting/restore-from-platform
- https://www.postgresql.org/download/windows/
- https://www.postgresql.org/docs/18/app-pgdump.html
- https://www.postgresql.org/docs/18/libpq-ssl.html
