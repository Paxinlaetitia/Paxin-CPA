# Núcleo Paxin — especificação visual

## Objetivo

Unificar a tela de acesso do aplicativo e o hero da página inicial do site com uma animação própria da marca Paxinbot. O núcleo representa uma única central coordenando instâncias, fluxos e registros.

## Composição

- Símbolo oficial Paxinbot no centro, em dourado sobre preto.
- Dois anéis orbitais com direções e velocidades diferentes.
- Módulos discretos distribuídos nas órbitas.
- Três identificadores: Instâncias, Fluxos e Registros.
- Movimento contínuo baseado somente em `transform` e `opacity`.

## Integração

- Aplicativo: layout de duas colunas inspirado na tela anterior, com identidade e núcleo à esquerda e autenticação à direita.
- Site: núcleo como visual principal do hero da página inicial.
- O componente não participa do login, não acessa APIs e não recebe dados do usuário.

## Requisitos não funcionais

- Recursos locais, sem CDN ou dependências externas.
- Pausa quando a janela fica oculta ou o componente sai da área visível.
- Respeito a `prefers-reduced-motion`.
- Sem animação de propriedades de layout ou filtros grandes.
- Responsivo para a janela mínima do aplicativo e para dispositivos móveis no site.

## Registro de decisões

1. Conceito escolhido: Núcleo Paxin.
2. Alternativas descartadas: janelas sincronizadas e fita dourada.
3. Motivo: comunica coordenação, preserva a marca e mantém baixa complexidade visual.
4. O fluxo de autenticação permanece inalterado.
5. A mesma implementação visual será reutilizada no site e no aplicativo.
