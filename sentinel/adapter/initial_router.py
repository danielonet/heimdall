"""First-boot router choice for installs from the published bundle.

A fresh install defaults to the Sagemcom adapter, which is wrong for most
people. `setup.sh --router=passive` writes INITIAL_ROUTER=passive into .env;
this applies it once, so the very first poll already uses the right adapter
and nothing tries to log in to a router that isn't a Sagemcom.
"""
from __future__ import annotations

import logging

from sentinel.adapter.factory import PASSIVE_ROUTER
from sentinel.config import settings

logger = logging.getLogger(__name__)


async def apply_initial_router(initial: str | None = None) -> str | None:
    """Select INITIAL_ROUTER as the primary router on a pristine install.

    Returns the router id it selected, or None if it did nothing. It only acts
    when ALL of these hold, so a restart can never override a later choice:
    a supported value is requested (today only 'passive'; every other router
    needs credentials the dashboard must collect), the router is not already
    picked, no device has ever been recorded, and the primary is still the
    out-of-the-box 'sagemcom'.
    """
    from sentinel.db.repositories import DeviceRepository, RouterProfileRepository, SettingsRepository

    initial = (settings.INITIAL_ROUTER if initial is None else initial).strip().lower()
    if not initial or initial == 'sagemcom':
        return None
    if initial != PASSIVE_ROUTER:
        logger.warning('INITIAL_ROUTER=%r is not supported (only "passive"); choose the router on the Equipment tab', initial)
        return None

    profiles, app_settings = RouterProfileRepository(), SettingsRepository()
    if await profiles.get(PASSIVE_ROUTER) is not None:
        return None
    if not await DeviceRepository().is_empty():
        return None
    if await app_settings.get_active_router() != 'sagemcom':
        return None

    await profiles.upsert(PASSIVE_ROUTER, host=None, username=None)
    await app_settings.set_active_router(PASSIVE_ROUTER)
    logger.info('First boot: primary router set to %s (INITIAL_ROUTER)', PASSIVE_ROUTER)
    return PASSIVE_ROUTER
