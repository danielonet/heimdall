"""Adapter factory for instantiating the correct router adapter based on configuration.

Heimdall supports two independently-configured routers (see
docs/router/network-topology.md): the Sagemcom is the permanent household
router and is always available; a second, optional Redmi/MiWiFi router can
be added via the Settings tab. Exactly one of them is the "active" router
(AppSettings.active_router) — the one that feeds the detection pipeline, WAN
bandwidth tracking, RuleEngine auto-block, and ARP/DHCP reconciliation (see
SentinelScheduler._ensure_adapter). The other, if configured, is only polled
for device/traffic visibility (SentinelScheduler._secondary_poll_job) — see
that method's docstring for why full threat detection isn't (yet) run
against it too.
"""

import logging

from sentinel.config import settings

from .base import RouterAdapter
from .mock.mock_adapter import MockMiwifiAdapter, MockSagemcomAdapter
from .sagemcom.xmo_adapter import SagemcomXmoAdapter

logger = logging.getLogger(__name__)

SUPPORTED_ROUTERS = ('sagemcom', 'miwifi')


async def miwifi_configured() -> bool:
    """True if a second (Redmi/MiWiFi) router has been configured, real or
    mocked — used both to decide whether to poll it at all and to restrict
    which values AppSettings.active_router / the Settings-tab dropdown will
    accept (see sentinel/api/routes/settings.py's `available_routers`).

    The IP is DB-backed (SettingsRepository.get_miwifi_ip, like
    router_username — changeable from the Settings tab without a restart),
    falling back to Settings.MIWIFI_IP only until an admin sets one there —
    same env-default-until-overridden shape as every other SettingsRepository
    field.
    """
    if settings.USE_MOCK_MIWIFI:
        return True
    from sentinel.db.repositories import SettingsRepository
    ip = await SettingsRepository().get_miwifi_ip()
    return bool(ip)


async def create_router_adapter(router: str | None = None) -> RouterAdapter:
    """Build the adapter for `router` ('sagemcom' | 'miwifi'), or for
    whichever router is currently AppSettings.active_router if `router`
    isn't given. This is "the" adapter — see this module's docstring.

    Raises:
        ValueError: If `router` isn't one of SUPPORTED_ROUTERS, or is
            'miwifi' while no MiWiFi credentials are configured.
    """
    if router is None:
        from sentinel.db.repositories import SettingsRepository
        router = await SettingsRepository().get_active_router()

    if router == 'sagemcom':
        return await _build_sagemcom_adapter()
    if router == 'miwifi':
        return await _build_miwifi_adapter()
    raise ValueError(f'Unknown router: {router!r} (expected one of {SUPPORTED_ROUTERS})')


async def create_secondary_router_adapter(active_router: str) -> RouterAdapter | None:
    """Build the adapter for whichever supported router is NOT
    `active_router` and is actually configured — used only for the
    lightweight, detection-pipeline-free visibility poll. Returns None when
    there's nothing to build (e.g. active_router is already 'sagemcom' and
    no MiWiFi credentials are configured — the common single-router case).
    """
    if active_router == 'sagemcom':
        if not await miwifi_configured():
            return None
        return await _build_miwifi_adapter()
    if active_router == 'miwifi':
        # Sagemcom is the permanent household router — always buildable.
        return await _build_sagemcom_adapter()
    return None


async def _build_sagemcom_adapter() -> RouterAdapter:
    if settings.USE_MOCK_ROUTER:
        logger.warning('⚠️  MOCK ROUTER ENABLED (USE_MOCK_ROUTER=true)')
        logger.warning('⚠️  Using synthetic test data instead of real router.')
        logger.warning('⚠️  This mode is for offline development only.')
        return MockSagemcomAdapter()

    router_ip = settings.ROUTER_IP
    if not router_ip:
        from .discovery import discover_gateway_ip
        router_ip = discover_gateway_ip()
        logger.info('Auto-discovered router IP: %s', router_ip)

    # Username is a runtime-overridable, non-secret setting (see
    # SettingsRepository.set_router_username, PATCH /api/settings) — read
    # fresh here so a change from the Settings tab applies to the next
    # adapter build. The password is deliberately NOT DB-backed (see
    # AppSettings.router_username's docstring) — PATCH /api/settings writes
    # it straight to Settings.ROUTER_PASSWORD_FILE and mutates settings.
    # ROUTER_PASSWORD in place, so reading it directly here already picks
    # up any change.
    from sentinel.db.repositories import SettingsRepository
    username = await SettingsRepository().get_router_username()

    logger.info('Connecting to Sagemcom router at %s:%s', router_ip, settings.ROUTER_PORT)
    return SagemcomXmoAdapter(
        router_ip=router_ip,
        password=settings.ROUTER_PASSWORD,
        router_port=settings.ROUTER_PORT,
        poll_interval_s=settings.POLL_INTERVAL_SECONDS,
        username=username,
    )


async def _build_miwifi_adapter() -> RouterAdapter:
    if settings.USE_MOCK_MIWIFI:
        logger.warning('⚠️  MOCK MIWIFI ROUTER ENABLED (USE_MOCK_MIWIFI=true)')
        logger.warning('⚠️  Using synthetic test data instead of a real Redmi router.')
        return MockMiwifiAdapter()

    # IP is DB-backed (like Sagemcom's username above) — read fresh so a
    # change from the Settings tab applies to the next adapter build. The
    # password is deliberately NOT DB-backed — PATCH /api/settings writes it
    # straight to Settings.MIWIFI_PASSWORD_FILE and mutates settings.
    # MIWIFI_PASSWORD in place, so reading it directly here already picks up
    # any change.
    from sentinel.db.repositories import SettingsRepository
    router_ip = await SettingsRepository().get_miwifi_ip()
    if not router_ip:
        raise ValueError(
            'No MiWiFi IP is configured — cannot build a MiwifiAdapter. '
            'Set it (and a password) from the Settings tab first.'
        )

    from sentinel.adapter.miwifi.miwifi_adapter import MiwifiAdapter
    logger.info('Connecting to MiWiFi router at %s', router_ip)
    return MiwifiAdapter(
        router_ip=router_ip,
        password=settings.MIWIFI_PASSWORD,
        poll_interval_s=settings.POLL_INTERVAL_SECONDS,
    )
