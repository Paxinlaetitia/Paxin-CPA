# Pacote de segurança 2

O Paxinbot passa a aceitar apenas manifests de instalação e descritores de
atualização assinados pela chave de release. O site publicará o descritor em
`/releases/stable-win32-x64.json` somente depois que o instalador final for
gerado e seu SHA-256 for assinado fora do aplicativo.

Ordem da publicação:

1. empacotar o diretório da aplicação;
2. gerar `resources/paxinbot-integrity.json` assinado;
3. construir o Setup contendo esse manifesto;
4. gerar e assinar o descritor usando o hash do Setup final;
5. publicar o Setup e o descritor na mesma operação de release;
6. validar a instalação em uma cópia limpa antes de promovê-la.

A chave privada não pertence ao GitHub, Vercel, site ou aplicativo. Ela fica
protegida pelo DPAPI na estação de release.
