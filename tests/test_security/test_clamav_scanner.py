import pyclamd
import pytest
import pytest_asyncio

from sentinel.security.clamav_scanner import ClamAvScanner

pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def scanner():
    instance = ClamAvScanner()
    if not await instance.ping():
        pytest.skip('clamd not reachable on localhost:3310')
    return instance


class TestPing:
    async def test_ping_succeeds_against_real_clamd(self, scanner):
        assert await scanner.ping() is True

    async def test_ping_fails_gracefully_for_unreachable_host(self):
        instance = ClamAvScanner(host='127.0.0.1', port=1)
        assert await instance.ping() is False


class TestScanBytes:
    async def test_clean_data_returns_none(self, scanner):
        result = await scanner.scan_bytes(b'hello world, nothing malicious here')
        assert result is None

    async def test_eicar_test_string_is_detected(self, scanner):
        result = await scanner.scan_bytes(pyclamd.ClamdNetworkSocket().EICAR())
        assert result is not None
        assert 'stream' in result
        assert result['stream'][0] == 'FOUND'
