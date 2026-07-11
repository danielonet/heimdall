import pytest

from sentinel.notifications import service as service_module
from sentinel.notifications.service import NotificationConfig, NotificationService

pytestmark = pytest.mark.asyncio


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
