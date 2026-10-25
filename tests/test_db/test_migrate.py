"""Tests for sentinel.db.migrate (container-startup migration runner)."""
from sentinel.db.migrate import MIGRATIONS_DIR, build_config


def test_build_config_points_at_packaged_migrations() -> None:
    config = build_config('postgresql+asyncpg://u:p@localhost/db')
    assert MIGRATIONS_DIR.is_dir()
    assert config.get_main_option('script_location') == str(MIGRATIONS_DIR)
    assert config.get_main_option('sqlalchemy.url') == 'postgresql+asyncpg://u:p@localhost/db'


def test_build_config_escapes_percent_for_configparser() -> None:
    config = build_config('postgresql+asyncpg://u:p%40ss@localhost/db')
    assert config.get_main_option('sqlalchemy.url') == 'postgresql+asyncpg://u:p%40ss@localhost/db'
