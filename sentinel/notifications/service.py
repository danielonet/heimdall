"""Push notifications (ntfy.sh) and email alerts.

Both channels are optional and independent — an unconfigured or failing
channel is logged and skipped, never raised, since a notification failure
must never block the rule/alert that triggered it.
"""
from __future__ import annotations

import asyncio
import logging
import smtplib
from dataclasses import dataclass
from email.message import EmailMessage

import httpx

logger = logging.getLogger(__name__)

_NTFY_PRIORITY = {'CRITICAL': 'urgent', 'WARNING': 'high', 'INFO': 'default'}


@dataclass
class NotificationConfig:
    ntfy_url: str = ''
    smtp_host: str = ''
    smtp_port: int = 587
    smtp_from: str = ''
    smtp_to: str = ''            # falls back to smtp_from if blank (notify yourself)
    smtp_username: str = ''
    smtp_password: str = ''
    smtp_use_tls: bool = True


class NotificationService:
    """Sends a message over every configured channel (ntfy, email)."""

    def __init__(self, config: NotificationConfig) -> None:
        self._ntfy_url = config.ntfy_url
        self._smtp_host = config.smtp_host
        self._smtp_port = config.smtp_port
        self._smtp_from = config.smtp_from
        self._smtp_to = config.smtp_to or config.smtp_from
        self._smtp_username = config.smtp_username
        self._smtp_password = config.smtp_password
        self._smtp_use_tls = config.smtp_use_tls

    async def notify(self, title: str, message: str, severity: str = 'WARNING') -> None:
        """Send to every configured channel. Never raises."""
        if self._ntfy_url:
            await self._send_ntfy(title, message, severity)
        if self._smtp_host and self._smtp_from:
            await asyncio.to_thread(self._send_email, title, message)

    async def _send_ntfy(self, title: str, message: str, severity: str) -> None:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(
                    self._ntfy_url,
                    content=message.encode('utf-8'),
                    headers={'Title': title, 'Priority': _NTFY_PRIORITY.get(severity, 'default')},
                )
                resp.raise_for_status()
        except Exception as exc:
            logger.warning('ntfy notification failed: %s', exc)

    def _send_email(self, subject: str, body: str) -> None:
        try:
            msg = EmailMessage()
            msg['Subject'] = f'Heimdall: {subject}'
            msg['From'] = self._smtp_from
            msg['To'] = self._smtp_to
            msg.set_content(body)

            with smtplib.SMTP(self._smtp_host, self._smtp_port, timeout=10) as server:
                if self._smtp_use_tls:
                    server.starttls()
                if self._smtp_username:
                    server.login(self._smtp_username, self._smtp_password)
                server.send_message(msg)
        except Exception as exc:
            logger.warning('Email notification failed: %s', exc)
