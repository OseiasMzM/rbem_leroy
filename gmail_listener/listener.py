"""Gmail listener implementation using IMAP."""
from __future__ import annotations

import argparse
import getpass
import imaplib
import logging
import os
import sys
import time
from dataclasses import dataclass, field
from email import message_from_bytes
from email.message import Message
from email.policy import default
from html.parser import HTMLParser
from typing import List, Optional, Sequence


class _HTMLStripper(HTMLParser):
    """Convert HTML content to plain text using the standard library."""

    def __init__(self) -> None:
        super().__init__()
        self._chunks: List[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:  # type: ignore[override]
        if tag in {"br", "p", "div"}:
            self._chunks.append("\n")

    def handle_endtag(self, tag: str) -> None:  # type: ignore[override]
        if tag in {"p", "div"}:
            self._chunks.append("\n")

    def handle_data(self, data: str) -> None:  # type: ignore[override]
        if data:
            self._chunks.append(data)

    def get_text(self) -> str:
        return "".join(self._chunks)


def _html_to_text(html: str) -> str:
    stripper = _HTMLStripper()
    stripper.feed(html)
    stripper.close()
    text = stripper.get_text()
    lines = [line.strip() for line in text.splitlines()]
    filtered = "\n".join(line for line in lines if line)
    return filtered if filtered else text.strip()


@dataclass
class IMAPListener:
    """Poll Gmail via IMAP for messages from a specific sender."""

    host: str
    username: str
    password: str
    mailbox: str = "INBOX"
    leave_unread: bool = False
    connection: Optional[imaplib.IMAP4_SSL] = field(init=False, default=None)
    processed_uids: set[str] = field(default_factory=set)

    def connect(self) -> imaplib.IMAP4_SSL:
        """Establish a connection to the IMAP server if needed."""
        if self.connection is None:
            logging.info("Connecting to %s as %s", self.host, self.username)
            conn = imaplib.IMAP4_SSL(self.host)
            conn.login(self.username, self.password)
            status, _ = conn.select(self.mailbox, readonly=self.leave_unread)
            if status != "OK":
                conn.logout()
                raise imaplib.IMAP4.error(f"Failed to select mailbox {self.mailbox}: {status}")
            self.connection = conn
        return self.connection

    def reconnect(self) -> imaplib.IMAP4_SSL:
        """Reconnect to the IMAP server, closing the previous session."""
        self.logout()
        return self.connect()

    def logout(self) -> None:
        """Close the IMAP connection if it is open."""
        if self.connection is None:
            return
        try:
            self.connection.close()
        except imaplib.IMAP4.error:
            pass
        try:
            self.connection.logout()
        except imaplib.IMAP4.error:
            pass
        finally:
            self.connection = None

    def fetch_new_messages(self, sender_email: str) -> List[str]:
        """Return UIDs for unseen messages from ``sender_email``."""
        conn = self.connect()
        criteria = f'(UNSEEN FROM "{sender_email}")'
        try:
            status, data = conn.uid("search", None, criteria)
        except imaplib.IMAP4.abort as exc:
            logging.warning("IMAP connection aborted while searching: %s", exc)
            conn = self.reconnect()
            status, data = conn.uid("search", None, criteria)

        if status != "OK" or not data:
            logging.debug("Search returned no data (status=%s)", status)
            return []

        uids_raw = data[0].split()
        uids = [uid.decode() if isinstance(uid, bytes) else uid for uid in uids_raw]
        uids.sort(key=int)
        new_uids = [uid for uid in uids if uid not in self.processed_uids]
        logging.debug("Found %d total UIDs, %d new", len(uids), len(new_uids))
        return new_uids

    def fetch_message_body(self, uid: str) -> Optional[str]:
        """Return the decoded body text for a message UID."""
        conn = self.connect()
        try:
            status, data = conn.uid("fetch", uid, "(BODY.PEEK[])")
        except imaplib.IMAP4.abort as exc:
            logging.warning("IMAP connection aborted while fetching %s: %s", uid, exc)
            conn = self.reconnect()
            status, data = conn.uid("fetch", uid, "(BODY.PEEK[])")

        if status != "OK" or not data:
            logging.error("Failed to fetch message %s (status=%s)", uid, status)
            return None

        raw_email: Optional[bytes] = None
        for part in data:
            if isinstance(part, tuple) and part[1]:
                raw_email = part[1]
                break
        if raw_email is None:
            logging.error("Empty payload returned for message %s", uid)
            return None

        message = message_from_bytes(raw_email, policy=default)
        body = _extract_message_body(message)
        if body is None:
            logging.info("Message %s does not contain text/plain or text/html parts", uid)
        return body

    def mark_as_seen(self, uid: str) -> None:
        """Mark the given message UID as read on the server."""
        if self.leave_unread:
            return
        conn = self.connect()
        try:
            status, _ = conn.uid("STORE", uid, "+FLAGS", "(\\Seen)")
        except imaplib.IMAP4.abort as exc:
            logging.warning("IMAP connection aborted while marking %s as seen: %s", uid, exc)
            conn = self.reconnect()
            status, _ = conn.uid("STORE", uid, "+FLAGS", "(\\Seen)")
        if status != "OK":
            logging.warning("Failed to mark message %s as seen (status=%s)", uid, status)

    def listen(self, sender_email: str, *, interval: int = 30) -> None:
        """Continuously poll for messages and print their body."""
        self.connect()
        logging.info(
            "Listening for unseen messages from %s in %s", sender_email, self.mailbox
        )
        while True:
            new_uids = self.fetch_new_messages(sender_email)
            for uid in new_uids:
                body = self.fetch_message_body(uid)
                if body:
                    print("=" * 80)
                    print(f"Message UID: {uid}")
                    print(body)
                    print("=" * 80)
                    sys.stdout.flush()
                self.mark_as_seen(uid)
                self.processed_uids.add(uid)
            time.sleep(interval)


def _extract_message_body(message: Message) -> Optional[str]:
    """Return text content from an e-mail message."""
    if message.is_multipart():
        for part in message.walk():
            if part.is_multipart():
                continue
            content_type = part.get_content_type()
            disposition = part.get_content_disposition()
            if disposition not in (None, "inline"):
                continue
            if content_type == "text/plain":
                try:
                    return part.get_content().strip()
                except Exception:  # pragma: no cover - defensive
                    return part.get_payload(decode=True).decode(errors="ignore").strip()
        for part in message.walk():
            if part.is_multipart():
                continue
            content_type = part.get_content_type()
            disposition = part.get_content_disposition()
            if disposition not in (None, "inline"):
                continue
            if content_type == "text/html":
                html = part.get_content()
                return _html_to_text(html)
    else:
        content_type = message.get_content_type()
        if content_type == "text/plain":
            return message.get_content().strip()
        if content_type == "text/html":
            return _html_to_text(message.get_content())
    return None


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Escuta e imprime e-mails de um remetente")
    parser.add_argument("--sender", required=True, help="Endereço do remetente a monitorar")
    parser.add_argument(
        "--username", required=True, help="Conta Gmail (endereço completo) usada para login"
    )
    parser.add_argument(
        "--password",
        help="Senha ou senha de app; se omitido usa IMAP_PASSWORD ou solicita via prompt",
    )
    parser.add_argument("--imap-host", default="imap.gmail.com", help="Host IMAP do Gmail")
    parser.add_argument("--mailbox", default="INBOX", help="Caixa a ser monitorada (padrão: INBOX)")
    parser.add_argument(
        "--interval", type=int, default=30, help="Intervalo em segundos entre verificações"
    )
    parser.add_argument(
        "--leave-unread",
        action="store_true",
        help="Não marcar as mensagens como lidas após processá-las",
    )
    parser.add_argument("--log-level", default="INFO", help="Nível de log (ex.: INFO, DEBUG)")
    return parser.parse_args(argv)


def _resolve_password(cli_password: Optional[str]) -> str:
    if cli_password:
        return cli_password
    env_password = os.getenv("IMAP_PASSWORD")
    if env_password:
        return env_password
    return getpass.getpass("Senha IMAP: ")


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(level=getattr(logging, args.log_level.upper(), logging.INFO))

    password = _resolve_password(args.password)
    listener = IMAPListener(
        host=args.imap_host,
        username=args.username,
        password=password,
        mailbox=args.mailbox,
        leave_unread=args.leave_unread,
    )

    try:
        listener.listen(args.sender, interval=args.interval)
    except KeyboardInterrupt:
        logging.info("Listener interrompido pelo usuário")
        return 0
    except imaplib.IMAP4.error as exc:
        logging.error("Erro IMAP: %s", exc)
        return 1
    finally:
        listener.logout()
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI behavior
    raise SystemExit(main())