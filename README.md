# Monitoramento de e-mails do Gmail

Este projeto fornece um pequeno utilitário em Python que fica monitorando a conta
Gmail autenticada e imprime o corpo de novos e-mails recebidos de um remetente
específico.

## Pré-requisitos

1. **Python 3.10+** instalado na máquina.
2. Uma conta Google com o Gmail habilitado.
3. A API do Gmail ativada para o projeto na [Google Cloud Console](https://console.cloud.google.com/apis/library/gmail.googleapis.com).
4. Um arquivo `credentials.json` (OAuth Client ID do tipo *Desktop App*) baixado
a partir da Google Cloud Console.

## Preparação do ambiente

1. Clone este repositório e navegue até a pasta do projeto.
2. Crie um ambiente virtual (opcional, mas recomendado):

   ```bash
   python -m venv .venv
   source .venv/bin/activate  # Linux/macOS
   .venv\Scripts\activate     # Windows PowerShell
   ```

3. Instale as dependências:

   ```bash
   pip install -r requirements.txt
   ```

4. Coloque o arquivo `credentials.json` na raiz do projeto (o arquivo **não**
devê ser commitado em controle de versão). Você pode utilizar o `.gitignore`
para garantir isso.

## Uso

Execute o listener informando o endereço de e-mail do remetente que você deseja
monitorar:

```bash
python -m gmail_listener.listener --sender remetente@example.com
```

Na primeira execução será aberta uma janela do navegador solicitando que você
faça login na conta Google e conceda acesso de leitura ao Gmail. Após a
autorização, o token é salvo em `token.json` para reutilização em execuções
futuras.

### Opções adicionais

- `--credentials`: Caminho para o arquivo `credentials.json` (padrão: `credentials.json`).
- `--token`: Caminho para armazenar o token de acesso (padrão: `token.json`).
- `--interval`: Intervalo em segundos entre as verificações (padrão: `30`).
- `--label`: Pode ser informado múltiplas vezes para filtrar por IDs de
  etiquetas específicas do Gmail (ex.: `INBOX`).
- `--log-level`: Controla o nível de logs exibidos (ex.: `DEBUG`).

Quando novos e-mails do remetente monitorado chegarem, o corpo do texto será
impresso no terminal dentro de um bloco delimitado por linhas `====`.

## Segurança

- Nunca compartilhe nem versione os arquivos `credentials.json` e `token.json`.
- Revogue o acesso às credenciais em
  [https://myaccount.google.com/permissions](https://myaccount.google.com/permissions)
  quando não precisar mais do aplicativo.

## Limitações

Este exemplo faz *polling* periódico à API do Gmail (não utiliza webhooks ou
Push Notifications). O intervalo padrão de 30 segundos pode ser ajustado via
parâmetro `--interval`.
