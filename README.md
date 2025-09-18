# Monitoramento de e-mails do Gmail via IMAP

Este projeto fornece um utilitário em Python que se conecta ao Gmail via IMAP,
fica monitorando a caixa escolhida e imprime o corpo de novos e-mails recebidos
de um remetente específico.

## Pré-requisitos

1. **Python 3.10+** instalado.
2. Uma conta Google com o Gmail habilitado.
3. O acesso IMAP ativado em [Configurações › Encaminhamento e POP/IMAP](https://mail.google.com/mail/u/0/#settings/fwdandpop).
4. Uma [senha de app](https://support.google.com/accounts/answer/185833) gerada para o Gmail
   (ou a senha da conta, se o segundo fator estiver desativado — não recomendado).

## Preparação do ambiente

1. Clone este repositório e navegue até a pasta do projeto.
2. (Opcional) Crie um ambiente virtual:

   ```bash
   python -m venv .venv
   source .venv/bin/activate  # Linux/macOS
   .venv\Scripts\activate     # Windows PowerShell
   ```

3. Não há dependências externas obrigatórias, mas o comando abaixo mantém a
   compatibilidade com a instalação padrão de projetos Python:

   ```bash
   pip install -r requirements.txt
   ```

## Uso

Execute o listener informando o remetente a monitorar, o endereço da conta e a
senha (ou senha de app). A senha pode ser passada pela opção `--password`, pela
variável de ambiente `IMAP_PASSWORD` ou digitada de forma interativa quando não
for fornecida explicitamente.

```bash
python -m gmail_listener.listener \
    --sender remetente@example.com \
    --username voce@gmail.com \
    --interval 30
```

Por padrão, o script monitora a caixa de entrada (`INBOX`) e marca as mensagens
processadas como lidas. Use `--leave-unread` se preferir mantê-las como não lidas
(elas continuarão aparecendo a cada execução enquanto permanecerem `UNSEEN`).

### Opções principais

- `--sender`: Endereço de e-mail do remetente a ser monitorado (obrigatório).
- `--username`: Conta Gmail utilizada para autenticar no IMAP (obrigatório).
- `--password`: Senha ou senha de app da conta. Se omitido, o script busca em
  `IMAP_PASSWORD` e, na ausência, solicitará via prompt seguro.
- `--interval`: Intervalo, em segundos, entre as verificações (padrão: `30`).
- `--imap-host`: Host IMAP; o padrão para o Gmail é `imap.gmail.com`.
- `--mailbox`: Caixa/pasta a monitorar (padrão: `INBOX`).
- `--leave-unread`: Não marca as mensagens como lidas após impressão.
- `--log-level`: Ajusta o nível de log (por exemplo, `DEBUG`).

### Saída

Quando novos e-mails do remetente monitorado chegarem, o corpo textual será
impresso no terminal dentro de um bloco delimitado por linhas `====`. Mensagens
HTML são convertidas para texto simples automaticamente.

## Segurança

- Nunca compartilhe nem versione senhas ou senhas de app. Prefira variáveis de
  ambiente ou gerenciadores de segredos.
- Revogue senhas de app que não forem mais necessárias na página de segurança da
  conta Google.

## Limitações

- O utilitário faz *polling* periódico (IMAP `search`), sem suporte a IDLE ou
  push notifications.
- Apenas partes `text/plain` ou `text/html` são exibidas. Anexos não são baixados
  nem processados.
