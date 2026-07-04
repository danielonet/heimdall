"""Adapter factory for instantiating the correct router adapter based on configuration."""

import logging

from sentinel.config import settings

from .base import RouterAdapter
from .mock.mock_adapter import MockSagemcomAdapter
from .sagemcom.xmo_adapter import SagemcomXmoAdapter

logger = logging.getLogger(__name__)


async def create_router_adapter() -> RouterAdapter:
    """Create and return the appropriate router adapter based on configuration.

    Returns:
        RouterAdapter: Either MockSagemcomAdapter (if USE_MOCK_ROUTER=true) or
                      SagemcomXmoAdapter (production).

    Raises:
        ValueError: If ROUTER_ADAPTER is not 'sagemcom'.
    """
    if settings.ROUTER_ADAPTER != 'sagemcom':
        raise ValueError(f'Unknown ROUTER_ADAPTER: {settings.ROUTER_ADAPTER}')

    if settings.USE_MOCK_ROUTER:
        logger.warning('⚠️  MOCK ROUTER ENABLED (USE_MOCK_ROUTER=true)')
        logger.warning('⚠️  Using synthetic test data instead of real router.')
        logger.warning('⚠️  This mode is for offline development only.')
        return MockSagemcomAdapter()

    # Production: connect to real router
    router_ip = settings.ROUTER_IP
    if not router_ip:
        from .discovery import discover_gateway_ip
        router_ip = discover_gateway_ip()
        logger.info('Auto-discovered router IP: %s', router_ip)

    logger.info('Connecting to Sagemcom router at %s:%s', router_ip, settings.ROUTER_PORT)
    return SagemcomXmoAdapter(
        router_ip=router_ip,
        password=settings.ROUTER_PASSWORD,
        router_port=settings.ROUTER_PORT,
        poll_interval_s=settings.POLL_INTERVAL_SECONDS,
    )
