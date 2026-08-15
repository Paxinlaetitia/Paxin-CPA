# Checkout Paxinbot v1

## Objetivo

Conectar os produtos já cadastrados à jornada pública de compra, preservar a
modalidade durante a autenticação e oferecer PIX dentro da Área do Cliente,
mantendo cartão e demais meios no Checkout Pro do Mercado Pago.

## Escopo

- Compra única; recorrência fica fora da primeira versão.
- O catálogo existente em `products` continua como fonte única de produto,
  preço, duração, moeda, descrição e disponibilidade.
- A URL transporta somente o UUID do produto. O servidor recalcula preço,
  cupom e total antes de criar qualquer cobrança.
- Nome e e-mail são os únicos dados de contato exibidos no checkout. Não há
  CPF nem endereço de cobrança no fluxo PIX.

## Jornada

1. O visitante escolhe um produto em `/planos`.
2. O navegador abre `/conta/checkout?product=<uuid>`.
3. Sem sessão, o documento exibe a autenticação e preserva o destino interno.
4. Login, cadastro, código por e-mail, Google e passkey retornam ao mesmo
   checkout.
5. Com sessão válida, a página carrega o produto do catálogo e permite aplicar
   cupom.
6. PIX cria uma order idempotente e exibe QR Code, Copia e Cola, vencimento e
   status. Cartão abre o Checkout Pro em nova aba.
7. Apenas Webhook autenticado e conciliação no servidor liberam o acesso.

## Segurança

- Access Token do Mercado Pago somente no backend.
- `X-Idempotency-Key` derivada do ID interno do pedido.
- Webhook com assinatura e janela temporal validadas.
- Valor, moeda, produto e cupom confirmados no banco.
- Finalização idempotente; notificações repetidas não duplicam saldo.
- Retorno de autenticação limitado a rotas internas conhecidas.
- QR e código PIX não são gravados em logs nem enviados por e-mail.

## Estados da interface

- Carregando produto.
- Produto indisponível.
- Revisão de contato e forma de pagamento.
- Cupom válido ou inválido junto ao campo.
- Criando cobrança, sem aceitar clique repetido.
- PIX aguardando, aprovado, expirado ou cancelado.
- Checkout Pro aberto em nova aba.
- Falha recuperável do provedor.

## Validação

- Testes de preservação do produto durante autenticação.
- Testes de preço e cupom recalculados no servidor.
- Testes de idempotência, Webhook duplicado e valor divergente.
- Testes dos estados PIX e do redirecionamento externo de cartão.
- Verificação responsiva em desktop e celular.

## Decisões

- Produtos existentes são reutilizados; não há tabela paralela de planos.
- PIX é interno; cartão e outros meios permanecem no Mercado Pago.
- Compras da v1 não renovam automaticamente.
- Acesso por tempo gera saldo ativável; vitalício é liberado imediatamente.
