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
from pathlib import Path

import httpx

logger = logging.getLogger(__name__)

_NTFY_PRIORITY = {'CRITICAL': 'urgent', 'WARNING': 'high', 'INFO': 'default'}

# Same PNG as frontend/src/assets/heimdall-icon.png — copied rather than
# referenced across the frontend/backend boundary so the backend package
# stays self-contained (no dependency on the frontend source tree existing
# at runtime). Keep both in sync if the logo ever changes. Embedded via
# Content-ID (see _send_email) rather than linked, since most email
# clients (Gmail included) block remote images by default but show
# inline/embedded ones automatically.
_LOGO_PATH = Path(__file__).parent / 'assets' / 'heimdall-icon.png'
_LOGO_CID = 'heimdall-logo'


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

    async def notify(
        self, title: str, message: str, severity: str = 'WARNING', html_message: str | None = None,
    ) -> None:
        """Send to every configured channel. Never raises.

        html_message, if given, is used as an HTML alternative for the
        email channel only — ntfy has no HTML story (a phone push
        notification has no room for one), so it always gets `message`
        as plain text regardless. A client that can't render HTML falls
        back to `message` too, via EmailMessage's own multipart/alternative
        handling in _send_email.
        """
        if self._ntfy_url:
            await self._send_ntfy(title, message, severity)
        if self._smtp_host and self._smtp_from:
            await asyncio.to_thread(self._send_email, title, message, html_message)

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

    async def notify_new_critical_alert(self, alert) -> None:
        """Immediate notification for a genuinely new CRITICAL alert — the
        real-time channel, distinct from SentinelScheduler._security_digest_job's
        once-a-day summary of everything regardless of severity.

        Requested directly: the Notifications page's own copy already
        claimed "Email alerts for CRITICAL/WARNING events" before this
        existed — confirmed live 2026-09-07 that nothing backed that
        claim, only the daily digest and one narrow AUTO_BLOCK_EXPIRED
        case ever called notify() at all. Scoped to CRITICAL only (not
        WARNING too, despite the old copy) — a deliberate choice to avoid
        flooding the inbox with the same WARNING-level noise (vendor
        mismatches, AP-tier crossings) trust-based suppression and the
        INFO/WARNING magnitude split were built earlier this project to
        cut down on.

        `alert` must be a just-persisted, genuinely NEW row (the "fire"
        transition) — never call this for a touch on an already-open
        alert; an ongoing CRITICAL condition already accumulates its own
        occurrence_count, and emailing on every poll it's still true would
        flood the inbox rather than inform it. Callers already have this
        distinction from AlertRepository.upsert()'s own is_new return.
        """
        if alert.severity != 'CRITICAL':
            return
        await self.notify(title=alert.alert_type, message=alert.description or alert.alert_type, severity='CRITICAL')

    def _send_email(self, subject: str, body: str, html_body: str | None = None) -> None:
        try:
            msg = EmailMessage()
            msg['Subject'] = f'Heimdall: {subject}'
            msg['From'] = self._smtp_from
            msg['To'] = self._smtp_to
            msg.set_content(body)

            if html_body:
                msg.add_alternative(html_body, subtype='html')
                # add_alternative() makes msg multipart/alternative with
                # [plain_part, html_part] — embed the logo inside the html
                # part specifically (add_related() wraps *that* part in its
                # own multipart/related), not the plain-text one, since a
                # plain-text client has no use for an image at all.
                if _LOGO_PATH.exists():
                    html_part = msg.get_payload()[1]
                    # RFC 2392/2045: a Content-ID header is conventionally
                    # angle-bracketed; add_related() doesn't add the
                    # brackets itself, so this does it explicitly for
                    # maximum client compatibility. The `cid:` URI in the
                    # HTML (digest.py's <img src="cid:heimdall-logo">) is
                    # the bare form — brackets are a header-only convention.
                    html_part.add_related(
                        _LOGO_PATH.read_bytes(), maintype='image', subtype='png', cid=f'<{_LOGO_CID}>',
                    )
                else:
                    logger.warning('Heimdall logo not found at %s — sending digest email without it', _LOGO_PATH)

            with smtplib.SMTP(self._smtp_host, self._smtp_port, timeout=10) as server:
                if self._smtp_use_tls:
                    server.starttls()
                if self._smtp_username:
                    server.login(self._smtp_username, self._smtp_password)
                server.send_message(msg)
        except Exception as exc:
            logger.warning('Email notification failed: %s', exc)
