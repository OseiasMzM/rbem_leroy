"""Example script to fetch unread messages from a specific sender using IMAP."""
from __future__ import annotations

from gmail_listener.listener import IMAPListener

# ----------------------------------------------------------------------------
# Configure your account credentials and the sender you want to monitor.
# Fill in the constants below with the appropriate values before running the
# script. These values are defined in the source code so no command-line
# arguments are necessary.
# ----------------------------------------------------------------------------
IMAP_HOST = "imap.gmail.com"
USERNAME = "seu_email@gmail.com"
PASSWORD = "sua_senha_ou_senha_de_app"
MAILBOX = "INBOX"
SENDER_EMAIL = "remetente@exemplo.com"


def main() -> None:
    """Fetch unseen messages from ``SENDER_EMAIL`` and print their content."""
    listener = IMAPListener(
        host=IMAP_HOST,
        username=USERNAME,
        password=PASSWORD,
        mailbox=MAILBOX,
        leave_unread=True,
    )

    try:
        message_uids = listener.fetch_new_messages(SENDER_EMAIL)
        if not message_uids:
            print("Nenhuma mensagem nova encontrada para o remetente especificado.")
            return

        for uid in message_uids:
            body = listener.fetch_message_body(uid)
            if body is None:
                print(f"Não foi possível obter o corpo da mensagem {uid}.")
                continue

            print("=" * 80)
            print(f"Mensagem UID: {uid}")
            print(body)
            print("=" * 80)

    finally:
        listener.logout()


if __name__ == "__main__":
    main()
