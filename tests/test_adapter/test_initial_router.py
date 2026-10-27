"""apply_initial_router: first-boot only, passive only, never overrides a later choice."""
from types import SimpleNamespace

import pytest

from sentinel.adapter.initial_router import apply_initial_router


@pytest.fixture
def state(monkeypatch):
    s = SimpleNamespace(profiles={}, devices_empty=True, active='sagemcom')

    class Profiles:
        async def get(self, router_id):
            return s.profiles.get(router_id)

        async def upsert(self, router_id, *, host, username):
            s.profiles[router_id] = SimpleNamespace(host=host or '')

    class Devices:
        async def is_empty(self):
            return s.devices_empty

    class Settings:
        async def get_active_router(self):
            return s.active

        async def set_active_router(self, router):
            s.active = router

    for name, cls in (('RouterProfileRepository', Profiles), ('DeviceRepository', Devices), ('SettingsRepository', Settings)):
        monkeypatch.setattr(f'sentinel.db.repositories.{name}', cls)
    return s


@pytest.mark.asyncio
async def test_selects_passive_on_a_pristine_install(state):
    assert await apply_initial_router('passive') == 'passive'
    assert state.active == 'passive' and 'passive' in state.profiles


@pytest.mark.asyncio
async def test_second_boot_does_nothing(state):
    await apply_initial_router('passive')
    state.active = 'sagemcom'  # admin switched the primary back
    assert await apply_initial_router('passive') is None
    assert state.active == 'sagemcom'


@pytest.mark.asyncio
async def test_never_touches_an_install_that_has_recorded_devices(state):
    state.devices_empty = False
    assert await apply_initial_router('passive') is None and state.active == 'sagemcom'


@pytest.mark.asyncio
async def test_never_overrides_another_primary(state):
    state.active = 'miwifi'
    assert await apply_initial_router('passive') is None and state.active == 'miwifi'


@pytest.mark.asyncio
@pytest.mark.parametrize('value', ['', 'sagemcom', 'openwrt-ubus', 'nonsense'])
async def test_ignores_unset_or_unsupported_values(state, value):
    assert await apply_initial_router(value) is None
    assert state.active == 'sagemcom' and not state.profiles
