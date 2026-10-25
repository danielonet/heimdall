from types import SimpleNamespace

import pytest

from sentinel.adapter import factory
from sentinel.adapter.asus.asus_adapter import AsusAdapter
from sentinel.adapter.netgear.netgear_adapter import NetgearAdapter
from sentinel.adapter.mikrotik.mikrotik_adapter import MikrotikAdapter
from sentinel.adapter.openwrt.openwrt_adapter import OpenwrtAdapter
from sentinel.adapter.opnsense.opnsense_adapter import OpnsenseAdapter
from sentinel.adapter.pfsense.pfsense_adapter import PfsenseAdapter
from sentinel.adapter.unifi.unifi_adapter import UnifiAdapter
from sentinel.config import settings


@pytest.fixture
def secrets(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, 'ROUTER_SECRETS_DIR', str(tmp_path))
    return tmp_path


def _profile(monkeypatch, host='10.0.0.1', username='admin'):
    class Repo:
        async def get(self, router_id):
            return SimpleNamespace(host=host, username=username) if host is not None else None
    monkeypatch.setattr('sentinel.db.repositories.RouterProfileRepository', Repo)


@pytest.mark.asyncio
@pytest.mark.parametrize('router_id,cls', [
    ('unifi-network', UnifiAdapter), ('opnsense-rest', OpnsenseAdapter), ('pfsense-rest', PfsenseAdapter),
    ('openwrt-ubus', OpenwrtAdapter), ('mikrotik-rest', MikrotikAdapter),
    ('netgear-soap', NetgearAdapter), ('asus-http', AsusAdapter),
])
async def test_builds_the_right_adapter(router_id, cls, secrets, monkeypatch):
    (secrets / f'{router_id}.txt').write_text('s3cret\n')
    _profile(monkeypatch)
    adapter = await factory.create_router_adapter(router_id)
    assert isinstance(adapter, cls)
    await adapter.aclose()


@pytest.mark.asyncio
async def test_missing_password_is_a_clear_error(secrets, monkeypatch):
    _profile(monkeypatch)
    with pytest.raises(ValueError, match='no saved password'):
        await factory.create_router_adapter('unifi-network')


@pytest.mark.asyncio
async def test_missing_profile_is_a_clear_error(secrets, monkeypatch):
    _profile(monkeypatch, host=None)
    with pytest.raises(ValueError, match='no saved host'):
        await factory.create_router_adapter('opnsense-rest')
