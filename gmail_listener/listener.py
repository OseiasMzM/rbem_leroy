"""Gmail listener implementation.

This module provides helpers to authenticate with the Gmail API and poll for
incoming messages from a specific sender.
"""
from __future__ import annotations

import argparse
import base64
import logging
import os
import sys
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import Resource, build
from googleapiclient.errors import HttpError

# If modifying these scopes, delete the saved token file.
SCOPES: Sequence[str] = ("https://www.googleapis.com/auth/gmail.readonly",)


@dataclass
class GmailListener:
    """Poll Gmail for messages from a target sender.

    Parameters
    ----------
    service:
        Authenticated Gmail API service instance.
    processed_messages:
        A set used to keep track of message IDs that have already been handled.
    """

    service: Resource
    processed_messages: set[str] = field(default_factory=set)

    def fetch_new_messages(self, sender_email: str, *, label_ids: Optional[Sequence[str]] = None) -> List[Dict[str, str]]:
        """Return message metadata dictionaries for unseen messages from ``sender_email``.

        Parameters
        ----------
        sender_email:
            Address of the sender that should trigger processing.
        label_ids:
            Optional list of Gmail label IDs to restrict the search (for example,
            ``["INBOX"]``).
        """
        query = f"from:{sender_email} newer_than:1d"
        try:
            response = (
                self.service.users()
                .messages()
                .list(userId="me", q=query, labelIds=label_ids, maxResults=10)
                .execute()
            )
        except HttpError as exc:  # pragma: no cover - network interaction
            logging.error("Failed to list messages: %s", exc)
            return []

        messages = response.get("messages", [])
        new_messages = [msg for msg in messages if msg["id"] not in self.processed_messages]
        logging.debug("Found %d messages matching query, %d new", len(messages), len(new_messages))
        return new_messages

    def get_message_body(self, message_id: str) -> Optional[str]:
        """Return the plain text body for ``message_id`` if available."""
        try:
            message = (
                self.service.users()
                .messages()
                .get(userId="me", id=message_id, format="full")
                .execute()
            )
        except HttpError as exc:  # pragma: no cover - network interaction
            logging.error("Failed to fetch message %s: %s", message_id, exc)
            return None

        payload = message.get("payload", {})
        body = _decode_payload(payload)
        if body is None:
            logging.info("Message %s does not contain a plain text body", message_id)
            return None
        return body

    def listen(self, sender_email: str, *, interval: int = 30, label_ids: Optional[Sequence[str]] = ("INBOX",)) -> None:
        """Continuously poll for messages and print their body to stdout."""
        logging.info("Listening for messages from %s", sender_email)
        try:
            while True:
                for message in self.fetch_new_messages(sender_email, label_ids=label_ids):
                    message_id = message["id"]
                    if message_id in self.processed_messages:
                        continue

                    body = self.get_message_body(message_id)
                    if body is not None:
                        print("=" * 80)
                        print(f"Message ID: {message_id}")
                        print(body)
                        print("=" * 80)
                        sys.stdout.flush()
                    self.processed_messages.add(message_id)

                time.sleep(interval)
        except KeyboardInterrupt:
            logging.info("Listener stopped by user")


def build_gmail_service(credentials_path: str, token_path: str) -> Resource:
    """Authenticate and return an authorized Gmail API service."""
    creds = load_credentials(credentials_path, token_path)
    return build("gmail", "v1", credentials=creds, cache_discovery=False)


def load_credentials(credentials_path: str, token_path: str) -> Credentials:
    """Load stored user credentials or run the OAuth flow if needed."""
    creds: Optional[Credentials] = None
    if os.path.exists(token_path):
        creds = Credentials.from_authorized_user_file(token_path, SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            logging.info("Refreshing Gmail credentials")
            creds.refresh(Request())
        else:
            logging.info("Launching OAuth flow; follow the instructions in the browser")
            flow = InstalledAppFlow.from_client_secrets_file(credentials_path, SCOPES)
            creds = flow.run_local_server(port=0)
        with open(token_path, "w", encoding="utf-8") as token_file:
            token_file.write(creds.to_json())
    return creds


def _decode_payload(payload: Dict) -> Optional[str]:
    """Extract the body text from a Gmail message payload."""
    mime_type = payload.get("mimeType", "")
    body = payload.get("body", {})
    data = body.get("data")

    if data and mime_type.startswith("text/plain"):
        return base64.urlsafe_b64decode(data.encode("utf-8")).decode("utf-8")

    for part in payload.get("parts", []) or []:
        text = _decode_payload(part)
        if text:
            return text
    return None


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Listen for Gmail messages from a sender")
    parser.add_argument("--sender", required=True, help="Email address to monitor")
    parser.add_argument(
        "--credentials",
        default="credentials.json",
        help="Path to the OAuth client credentials file",
    )
    parser.add_argument(
        "--token",
        default="token.json",
        help="Path to store the generated user token",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=30,
        help="Polling interval in seconds",
    )
    parser.add_argument(
        "--label",
        action="append",
        dest="labels",
        help="Restrict the search to the given Gmail label ID (can be specified multiple times)",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        help="Logging level (e.g. INFO, DEBUG)",
    )
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Entry-point used when the module is executed as a script."""
    args = parse_args(argv)
    logging.basicConfig(level=getattr(logging, args.log_level.upper(), logging.INFO))

    try:
        service = build_gmail_service(args.credentials, args.token)
    except FileNotFoundError:
        logging.error("Credentials file %s not found", args.credentials)
        return 1
    except HttpError as exc:  # pragma: no cover - network interaction
        logging.error("Failed to initialize Gmail service: %s", exc)
        return 1

    listener = GmailListener(service=service)
    listener.listen(args.sender, interval=args.interval, label_ids=args.labels)
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI behavior
    raise SystemExit(main())
