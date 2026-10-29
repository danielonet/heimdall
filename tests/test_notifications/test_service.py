from types import SimpleNamespace

import pytest

from sentinel.notifications import service as service_module
from sentinel.notifications.service import NotificationConfig, NotificationService

pytestmark = pytest.mark.asyncio


def _alert(
    severity='CRITICAL', alert_type='ARP_SPOOF', description='something happened',
    device_mac=None, mitigation=None, created_at=None,
):
    """A plain stand-in for a persisted Alert row. device_mac defaults to
    None so notify_new_critical_alert's `if alert.device_mac:` guard skips
    the DB lookup entirely — keeps most of this file's tests DB-free, same
    as before; TestNotifyNewCriticalAlert's own DB-backed cases override it
    explicitly with a real MAC."""
    return SimpleNamespace(
        severity=severity, alert_type=alert_type, description=description,
        device_mac=device_mac, mitigation=mitigation, created_at=created_at,
    )


class _FakeResponse:
    def raise_for_status(self):
        pass


class _FakeAsyncClient:
    """Records every POST made through it; replaces httpx.AsyncClient in tests."""

    calls = []

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc_info):
        return False

    async def post(self, url, content=None, headers=None):
        _FakeAsyncClient.calls.append({'url': url, 'content': content, 'headers': headers})
        return _FakeResponse()


class _FailingAsyncClient(_FakeAsyncClient):
    async def post(self, url, content=None, headers=None):
        raise ConnectionError('ntfy unreachable')


class _FakeSMTP:
    """Records every email 'sent' through it; replaces smtplib.SMTP in tests."""

    sent_messages = []
    login_calls = []
    starttls_called = False

    def __init__(self, host, port, timeout=None):
        self.host = host
        self.port = port

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False

    def starttls(self):
        _FakeSMTP.starttls_called = True

    def login(self, username, password):
        _FakeSMTP.login_calls.append((username, password))

    def send_message(self, msg):
        _FakeSMTP.sent_messages.append(msg)


@pytest.fixture(autouse=True)
def _reset_fakes():
    _FakeAsyncClient.calls = []
    _FakeSMTP.sent_messages = []
    _FakeSMTP.login_calls = []
    _FakeSMTP.starttls_called = False
    yield


class TestNtfyNotification:
    async def test_sends_when_configured(self, monkeypatch):
        monkeypatch.setattr(service_module.httpx, 'AsyncClient', _FakeAsyncClient)
        notifier = NotificationService(NotificationConfig(ntfy_url='https://ntfy.sh/test-topic'))

        await notifier.notify(title='Test Alert', message='something happened', severity='CRITICAL')

        assert len(_FakeAsyncClient.calls) == 1
        call = _FakeAsyncClient.calls[0]
        assert call['url'] == 'https://ntfy.sh/test-topic'
        assert call['content'] == b'something happened'
        assert call['headers']['Title'] == 'Test Alert'
        assert call['headers']['Priority'] == 'urgent'  # CRITICAL -> urgent

    async def test_priority_mapping(self, monkeypatch):
        monkeypatch.setattr(service_module.httpx, 'AsyncClient', _FakeAsyncClient)
        notifier = NotificationService(NotificationConfig(ntfy_url='https://ntfy.sh/test-topic'))

        await notifier.notify('t', 'm', severity='WARNING')
        assert _FakeAsyncClient.calls[-1]['headers']['Priority'] == 'high'

        await notifier.notify('t', 'm', severity='INFO')
        assert _FakeAsyncClient.calls[-1]['headers']['Priority'] == 'default'

    async def test_skipped_when_unconfigured(self, monkeypatch):
        monkeypatch.setattr(service_module.httpx, 'AsyncClient', _FakeAsyncClient)
        notifier = NotificationService(NotificationConfig(ntfy_url=''))

        await notifier.notify('t', 'm')
        assert _FakeAsyncClient.calls == []

    async def test_failure_does_not_raise(self, monkeypatch):
        monkeypatch.setattr(service_module.httpx, 'AsyncClient', _FailingAsyncClient)
        notifier = NotificationService(NotificationConfig(ntfy_url='https://ntfy.sh/test-topic'))

        await notifier.notify('t', 'm')  # must not raise


class TestEmailNotification:
    async def test_sends_when_configured(self, monkeypatch):
        monkeypatch.setattr(service_module.smtplib, 'SMTP', _FakeSMTP)
        notifier = NotificationService(NotificationConfig(
            smtp_host='smtp.example.com', smtp_from='heimdall@example.com',
        ))

        await notifier.notify(title='Test Alert', message='body text')

        assert len(_FakeSMTP.sent_messages) == 1
        msg = _FakeSMTP.sent_messages[0]
        assert msg['Subject'] == 'Heimdall: Test Alert'
        assert msg['From'] == 'heimdall@example.com'
        assert msg['To'] == 'heimdall@example.com'  # falls back to smtp_from

    async def test_smtp_to_overrides_fallback(self, monkeypatch):
        monkeypatch.setattr(service_module.smtplib, 'SMTP', _FakeSMTP)
        notifier = NotificationService(NotificationConfig(
            smtp_host='smtp.example.com', smtp_from='heimdall@example.com',
            smtp_to='me@example.com',
        ))

        await notifier.notify('t', 'm')
        assert _FakeSMTP.sent_messages[0]['To'] == 'me@example.com'

    async def test_starttls_used_by_default(self, monkeypatch):
        monkeypatch.setattr(service_module.smtplib, 'SMTP', _FakeSMTP)
        notifier = NotificationService(NotificationConfig(
            smtp_host='smtp.example.com', smtp_from='heimdall@example.com',
        ))
        await notifier.notify('t', 'm')
        assert _FakeSMTP.starttls_called is True

    async def test_starttls_skipped_when_disabled(self, monkeypatch):
        monkeypatch.setattr(service_module.smtplib, 'SMTP', _FakeSMTP)
        notifier = NotificationService(NotificationConfig(
            smtp_host='smtp.example.com', smtp_from='heimdall@example.com',
            smtp_use_tls=False,
        ))
        await notifier.notify('t', 'm')
        assert _FakeSMTP.starttls_called is False

    async def test_login_used_when_credentials_configured(self, monkeypatch):
        monkeypatch.setattr(service_module.smtplib, 'SMTP', _FakeSMTP)
        notifier = NotificationService(NotificationConfig(
            smtp_host='smtp.example.com', smtp_from='heimdall@example.com',
            smtp_username='user', smtp_password='pass',
        ))
        await notifier.notify('t', 'm')
        assert _FakeSMTP.login_calls == [('user', 'pass')]

    async def test_skipped_when_unconfigured(self, monkeypatch):
        monkeypatch.setattr(service_module.smtplib, 'SMTP', _FakeSMTP)
        notifier = NotificationService(NotificationConfig())

        await notifier.notify('t', 'm')
        assert _FakeSMTP.sent_messages == []

    async def test_failure_does_not_raise(self, monkeypatch):
        class _RaisingSMTP(_FakeSMTP):
            def __enter__(self):
                raise ConnectionError('smtp unreachable')

        monkeypatch.setattr(service_module.smtplib, 'SMTP', _RaisingSMTP)
        notifier = NotificationService(NotificationConfig(
            smtp_host='smtp.example.com', smtp_from='heimdall@example.com',
        ))
        await notifier.notify('t', 'm')  # must not raise

    async def test_no_html_message_sends_plain_text_only(self, monkeypatch):
        monkeypatch.setattr(service_module.smtplib, 'SMTP', _FakeSMTP)
        notifier = NotificationService(NotificationConfig(
            smtp_host='smtp.example.com', smtp_from='heimdall@example.com',
        ))
        await notifier.notify('t', 'm')  # no html_message given, same as every test above

        msg = _FakeSMTP.sent_messages[0]
        assert msg.is_multipart() is False

    async def test_html_message_sends_a_multipart_alternative_with_embedded_logo(self, monkeypatch):
        monkeypatch.setattr(service_module.smtplib, 'SMTP', _FakeSMTP)
        notifier = NotificationService(NotificationConfig(
            smtp_host='smtp.example.com', smtp_from='heimdall@example.com',
        ))

        await notifier.notify('t', 'plain body', html_message='<html><body>rich body</body></html>')

        msg = _FakeSMTP.sent_messages[0]
        assert msg.get_body(preferencelist=('plain',)).get_content().strip() == 'plain body'
        html_part = msg.get_body(preferencelist=('html',))
        assert 'rich body' in html_part.get_content()
        # The logo must be embedded (Content-ID) inside the html alternative
        # specifically, matching cid:heimdall-logo referenced in digest.py's
        # HTML — a plain-text client has no use for the image at all.
        related = [p for p in msg.walk() if p.get_content_type() == 'image/png']
        assert len(related) == 1
        assert related[0]['Content-ID'] == '<heimdall-logo>'

    async def test_missing_logo_file_still_sends_the_html_email(self, monkeypatch, tmp_path):
        """A missing logo must degrade gracefully — never block the whole
        digest email over one missing asset."""
        monkeypatch.setattr(service_module.smtplib, 'SMTP', _FakeSMTP)
        monkeypatch.setattr(service_module, '_LOGO_PATH', tmp_path / 'does-not-exist.png')
        notifier = NotificationService(NotificationConfig(
            smtp_host='smtp.example.com', smtp_from='heimdall@example.com',
        ))

        await notifier.notify('t', 'plain body', html_message='<html><body>rich body</body></html>')

        assert len(_FakeSMTP.sent_messages) == 1
        msg = _FakeSMTP.sent_messages[0]
        assert 'rich body' in msg.get_body(preferencelist=('html',)).get_content()
        assert [p for p in msg.walk() if p.get_content_type() == 'image/png'] == []


class TestNotifyNewCriticalAlert:
    """The real-time channel a genuinely new CRITICAL alert goes through —
    distinct from the daily digest's notify() call, which fires regardless
    of severity once a day. Requested directly after the Notifications
    page's own copy claimed this already happened and it didn't."""

    async def test_critical_alert_sends_over_both_channels(self, monkeypatch):
        monkeypatch.setattr(service_module.smtplib, 'SMTP', _FakeSMTP)
        monkeypatch.setattr(service_module.httpx, 'AsyncClient', _FakeAsyncClient)
        notifier = NotificationService(NotificationConfig(
            ntfy_url='https://ntfy.sh/test-topic',
            smtp_host='smtp.example.com', smtp_from='heimdall@example.com',
        ))

        await notifier.notify_new_critical_alert(_alert(severity='CRITICAL', alert_type='ARP_SPOOF'))

        assert len(_FakeSMTP.sent_messages) == 1
        assert _FakeSMTP.sent_messages[0]['Subject'] == 'Heimdall: ARP_SPOOF'
        assert len(_FakeAsyncClient.calls) == 1
        assert _FakeAsyncClient.calls[0]['headers']['Priority'] == 'urgent'

    async def test_warning_alert_sends_nothing(self, monkeypatch):
        """Deliberately scoped to CRITICAL only — WARNING/INFO stay
        digest-only, so family devices' routine WARNING findings don't
        flood the inbox the same way trust-based suppression and the
        INFO/WARNING magnitude split were built to cut down on."""
        monkeypatch.setattr(service_module.smtplib, 'SMTP', _FakeSMTP)
        monkeypatch.setattr(service_module.httpx, 'AsyncClient', _FakeAsyncClient)
        notifier = NotificationService(NotificationConfig(
            ntfy_url='https://ntfy.sh/test-topic',
            smtp_host='smtp.example.com', smtp_from='heimdall@example.com',
        ))

        await notifier.notify_new_critical_alert(_alert(severity='WARNING'))

        assert _FakeSMTP.sent_messages == []
        assert _FakeAsyncClient.calls == []

    async def test_info_alert_sends_nothing(self, monkeypatch):
        monkeypatch.setattr(service_module.smtplib, 'SMTP', _FakeSMTP)
        notifier = NotificationService(NotificationConfig(
            smtp_host='smtp.example.com', smtp_from='heimdall@example.com',
        ))

        await notifier.notify_new_critical_alert(_alert(severity='INFO'))

        assert _FakeSMTP.sent_messages == []

    async def test_uses_the_alert_type_as_the_title_and_description_in_the_body(self, monkeypatch):
        monkeypatch.setattr(service_module.smtplib, 'SMTP', _FakeSMTP)
        notifier = NotificationService(NotificationConfig(
            smtp_host='smtp.example.com', smtp_from='heimdall@example.com',
        ))

        await notifier.notify_new_critical_alert(
            _alert(severity='CRITICAL', alert_type='MALWARE_DETECTED', description='eicar.txt quarantined')
        )

        msg = _FakeSMTP.sent_messages[0]
        assert msg['Subject'] == 'Heimdall: MALWARE_DETECTED'
        # Enriched body (see TestFormattedBody below), not an exact match —
        # description is one line of several now, not the whole body.
        assert 'eicar.txt quarantined' in msg.get_body(preferencelist=('plain',)).get_content()

    async def test_falls_back_to_alert_type_when_description_is_blank(self, monkeypatch):
        monkeypatch.setattr(service_module.smtplib, 'SMTP', _FakeSMTP)
        notifier = NotificationService(NotificationConfig(
            smtp_host='smtp.example.com', smtp_from='heimdall@example.com',
        ))

        await notifier.notify_new_critical_alert(_alert(severity='CRITICAL', alert_type='NEW_DEVICE', description=None))

        body = _FakeSMTP.sent_messages[0].get_body(preferencelist=('plain',)).get_content()
        assert 'NEW_DEVICE' in body


class TestFormattedBody:
    """Regression coverage for a real, confirmed-live bug (2026-09-11):
    notify_new_critical_alert never passed html_message to notify() at
    all, so every real-time CRITICAL email went out as a bare, unformatted
    one-line body — no device, no trust status, no mitigation, no
    branding. See sentinel/notifications/alert_notification.py."""

    async def test_html_alternative_is_now_sent(self, monkeypatch):
        monkeypatch.setattr(service_module.smtplib, 'SMTP', _FakeSMTP)
        notifier = NotificationService(NotificationConfig(
            smtp_host='smtp.example.com', smtp_from='heimdall@example.com',
        ))

        await notifier.notify_new_critical_alert(_alert(alert_type='ARP_SPOOF', description='spoofing suspected'))

        msg = _FakeSMTP.sent_messages[0]
        assert msg.is_multipart() is True
        html = msg.get_body(preferencelist=('html',)).get_content()
        assert 'spoofing suspected' in html
        assert 'ARP_SPOOF' in html

    async def test_mitigation_appears_in_both_bodies_when_present(self, monkeypatch):
        monkeypatch.setattr(service_module.smtplib, 'SMTP', _FakeSMTP)
        notifier = NotificationService(NotificationConfig(
            smtp_host='smtp.example.com', smtp_from='heimdall@example.com',
        ))

        await notifier.notify_new_critical_alert(_alert(mitigation='Physically find and remove it from the network.'))

        msg = _FakeSMTP.sent_messages[0]
        assert 'Physically find and remove it' in msg.get_body(preferencelist=('plain',)).get_content()
        assert 'Physically find and remove it' in msg.get_body(preferencelist=('html',)).get_content()

    async def test_no_mitigation_omits_the_section_cleanly(self, monkeypatch):
        monkeypatch.setattr(service_module.smtplib, 'SMTP', _FakeSMTP)
        notifier = NotificationService(NotificationConfig(
            smtp_host='smtp.example.com', smtp_from='heimdall@example.com',
        ))

        await notifier.notify_new_critical_alert(_alert(mitigation=None))

        html = _FakeSMTP.sent_messages[0].get_body(preferencelist=('html',)).get_content()
        assert 'MITIGATION' not in html

    async def test_no_device_mac_skips_the_db_lookup_and_still_sends(self, monkeypatch):
        """device_mac=None (e.g. a household-wide finding, not one scoped
        to a single device) must never crash trying to look one up."""
        monkeypatch.setattr(service_module.smtplib, 'SMTP', _FakeSMTP)
        notifier = NotificationService(NotificationConfig(
            smtp_host='smtp.example.com', smtp_from='heimdall@example.com',
        ))

        await notifier.notify_new_critical_alert(_alert(device_mac=None))

        assert len(_FakeSMTP.sent_messages) == 1

    async def test_device_info_and_trust_status_appear_when_device_mac_resolves(self, monkeypatch):
        """The actual point of the fix — device context and trust status,
        neither of which the old bare-description body ever carried."""
        import os
        os.environ.setdefault('DATABASE_URL', 'postgresql+asyncpg://sentinel:pass@localhost/sentinel')
        from flask import Flask
        from sqlalchemy import delete
        from sentinel.db.models import Device
        from sentinel.db.session import get_engine, get_session, init_db

        mac = '44:44:44:44:44:03'
        app = Flask(__name__)
        app.config['DATABASE_URL'] = os.environ['DATABASE_URL']
        init_db(app)
        try:
            async with get_session() as session:
                session.add(Device(
                    mac_address=mac, hostname='untrusted-cam', vendor_name='Acme IoT', is_trusted=False,
                ))

            monkeypatch.setattr(service_module.smtplib, 'SMTP', _FakeSMTP)
            notifier = NotificationService(NotificationConfig(
                smtp_host='smtp.example.com', smtp_from='heimdall@example.com',
            ))

            await notifier.notify_new_critical_alert(_alert(device_mac=mac))

            msg = _FakeSMTP.sent_messages[0]
            plain = msg.get_body(preferencelist=('plain',)).get_content()
            html = msg.get_body(preferencelist=('html',)).get_content()
            assert 'untrusted-cam' in plain
            assert 'UNTRUSTED' in plain
            assert 'untrusted-cam' in html
            assert 'UNTRUSTED' in html
            assert 'Acme IoT' in html
        finally:
            async with get_session() as session:
                await session.execute(delete(Device).where(Device.mac_address == mac))
            await get_engine().dispose()


class _TelegramResponse:
    def __init__(self, status_code=200, body=None):
        self.status_code = status_code
        self._body = body if body is not None else {'ok': True}

    def json(self):
        return self._body


def _telegram_client(response=None, error=None):
    """An httpx.AsyncClient stand-in that records the JSON POSTs sent to Telegram."""
    calls = []

    class _Client:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc_info):
            return False

        async def post(self, url, json=None):
            calls.append({'url': url, 'json': json})
            if error is not None:
                raise error
            return response or _TelegramResponse()

    return _Client, calls


_TOKEN = '123456:ABCdefGhIJKlmNoPQRsTUVwxyZ-0123456'


class TestTelegramNotification:
    async def test_posts_title_and_message_to_the_configured_chat(self, monkeypatch):
        client, calls = _telegram_client()
        monkeypatch.setattr(service_module.httpx, 'AsyncClient', client)
        notifier = NotificationService(NotificationConfig(telegram_bot_token=_TOKEN, telegram_chat_id='@homealerts'))

        await notifier.notify('ARP_SPOOF', 'something happened', severity='CRITICAL')

        assert len(calls) == 1
        assert calls[0]['url'] == f'https://api.telegram.org/bot{_TOKEN}/sendMessage'
        assert calls[0]['json']['chat_id'] == '@homealerts'
        assert calls[0]['json']['text'] == 'ARP_SPOOF\n\nsomething happened'

    async def test_skipped_without_token_or_chat(self, monkeypatch):
        client, calls = _telegram_client()
        monkeypatch.setattr(service_module.httpx, 'AsyncClient', client)
        await NotificationService(NotificationConfig(telegram_chat_id='@x')).notify('t', 'm')
        await NotificationService(NotificationConfig(telegram_bot_token=_TOKEN)).notify('t', 'm')
        assert calls == []

    async def test_long_message_is_cut_to_telegrams_limit(self, monkeypatch):
        client, calls = _telegram_client()
        monkeypatch.setattr(service_module.httpx, 'AsyncClient', client)
        notifier = NotificationService(NotificationConfig(telegram_bot_token=_TOKEN, telegram_chat_id='@x'))
        await notifier.notify('t', 'x' * 10000)
        assert len(calls[0]['json']['text']) == 4096

    async def test_refusal_is_reported_without_the_token(self, monkeypatch):
        client, _ = _telegram_client(_TelegramResponse(401, {'ok': False, 'description': 'Unauthorized'}))
        monkeypatch.setattr(service_module.httpx, 'AsyncClient', client)
        notifier = NotificationService(NotificationConfig(telegram_bot_token=_TOKEN, telegram_chat_id='@x'))

        error = await notifier.send_telegram('t', 'm')

        assert error == 'Telegram refused the message (HTTP 401): Unauthorized'
        assert _TOKEN not in error

    async def test_network_failure_does_not_raise_or_leak_the_token(self, monkeypatch):
        error = service_module.httpx.ConnectError(f'cannot connect to https://api.telegram.org/bot{_TOKEN}/sendMessage')
        client, _ = _telegram_client(error=error)
        monkeypatch.setattr(service_module.httpx, 'AsyncClient', client)
        notifier = NotificationService(NotificationConfig(telegram_bot_token=_TOKEN, telegram_chat_id='@x'))

        await notifier.notify('t', 'm')  # must not raise
        reason = await notifier.send_telegram('t', 'm')
        assert reason == 'Could not reach Telegram (ConnectError).'
        assert _TOKEN not in reason

    async def test_send_telegram_says_when_unconfigured(self):
        reason = await NotificationService(NotificationConfig()).send_telegram('t', 'm')
        assert 'not configured' in reason
