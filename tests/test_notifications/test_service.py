from types import SimpleNamespace

import pytest

from sentinel.notifications import service as service_module
from sentinel.notifications.service import NotificationConfig, NotificationService

pytestmark = pytest.mark.asyncio


def _alert(severity='CRITICAL', alert_type='ARP_SPOOF', description='something happened'):
    """A plain stand-in for a persisted Alert row — notify_new_critical_alert
    only ever reads .severity/.alert_type/.description, so a real DB row
    isn't needed here."""
    return SimpleNamespace(severity=severity, alert_type=alert_type, description=description)


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

    async def test_uses_the_alert_type_as_the_title_and_description_as_the_body(self, monkeypatch):
        monkeypatch.setattr(service_module.smtplib, 'SMTP', _FakeSMTP)
        notifier = NotificationService(NotificationConfig(
            smtp_host='smtp.example.com', smtp_from='heimdall@example.com',
        ))

        await notifier.notify_new_critical_alert(
            _alert(severity='CRITICAL', alert_type='MALWARE_DETECTED', description='eicar.txt quarantined')
        )

        msg = _FakeSMTP.sent_messages[0]
        assert msg['Subject'] == 'Heimdall: MALWARE_DETECTED'
        assert msg.get_content().strip() == 'eicar.txt quarantined'

    async def test_falls_back_to_alert_type_when_description_is_blank(self, monkeypatch):
        monkeypatch.setattr(service_module.smtplib, 'SMTP', _FakeSMTP)
        notifier = NotificationService(NotificationConfig(
            smtp_host='smtp.example.com', smtp_from='heimdall@example.com',
        ))

        await notifier.notify_new_critical_alert(_alert(severity='CRITICAL', alert_type='NEW_DEVICE', description=None))

        assert _FakeSMTP.sent_messages[0].get_content().strip() == 'NEW_DEVICE'
