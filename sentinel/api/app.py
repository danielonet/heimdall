import logging
import os

from flask import Flask

from sentinel.api.extensions import jwt_manager, socketio
from sentinel.config import settings
from sentinel.db.session import init_db
from sentinel.scheduler.scheduler import init_scheduler

from sentinel.api.routes import alerts, auth, devices, ports, rules, system, threats
from sentinel.api.routes import settings as settings_routes

logger = logging.getLogger(__name__)


def create_app(config: dict | None = None) -> Flask:
    """Flask application factory.

    Args:
        config: Optional dict of config overrides (useful for testing).
    """
    app = Flask(__name__)
    app.config.from_object(settings)
    app.config['JWT_BLOCKLIST_ENABLED'] = True
    app.config['JWT_BLOCKLIST_TOKEN_CHECKS'] = ['access', 'refresh']
    if config:
        app.config.update(config)

    _configure_logging(app)

    jwt_manager.init_app(app)
    socketio.init_app(app)
    init_db(app)

    # Under the Werkzeug reloader (--debug), the parent "monitor" process
    # doesn't set WERKZEUG_RUN_MAIN — only the actual reloaded worker does.
    # Without this guard the scheduler would start twice.
    reloader_worker = not app.debug or os.environ.get('WERKZEUG_RUN_MAIN') == 'true'
    if app.config.get('SCHEDULER_ENABLED', True) and reloader_worker:
        init_scheduler(app)

    app.register_blueprint(auth.bp,    url_prefix='/api')
    app.register_blueprint(devices.bp, url_prefix='/api/devices')
    app.register_blueprint(alerts.bp,  url_prefix='/api/alerts')
    app.register_blueprint(rules.bp,   url_prefix='/api/rules')
    app.register_blueprint(ports.bp,   url_prefix='/api/ports')
    app.register_blueprint(threats.bp, url_prefix='/api/threats')
    app.register_blueprint(system.bp,  url_prefix='/api')
    app.register_blueprint(settings_routes.bp, url_prefix='/api/settings')

    logger.info('Heimdall sentinel API ready')
    return app


def _configure_logging(app: Flask) -> None:
    """Apply structured logging configuration from app config."""
    level = logging.DEBUG if app.config.get('DEBUG') else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s %(levelname)s %(name)s %(message)s',
    )
