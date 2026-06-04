import logging

from flask import Flask
from flask_jwt_extended import JWTManager
from flask_socketio import SocketIO

from sentinel.db.session import init_db

from sentinel.api.routes import alerts, auth, devices, ports, rules, threats

logger = logging.getLogger(__name__)

# Module-level SocketIO instance so websocket.py can import it without a
# circular import. init_app() is called inside create_app().
socketio = SocketIO(cors_allowed_origins='*', async_mode='threading')


def create_app(config: dict | None = None) -> Flask:
    """Flask application factory.

    Args:
        config: Optional dict of config overrides (useful for testing).
    """
    app = Flask(__name__)
    app.config.from_object('sentinel.config.Settings')
    if config:
        app.config.update(config)

    _configure_logging(app)

    JWTManager(app)
    socketio.init_app(app)
    init_db(app)

    app.register_blueprint(auth.bp,    url_prefix='/api')
    app.register_blueprint(devices.bp, url_prefix='/api/devices')
    app.register_blueprint(alerts.bp,  url_prefix='/api/alerts')
    app.register_blueprint(rules.bp,   url_prefix='/api/rules')
    app.register_blueprint(ports.bp,   url_prefix='/api/ports')
    app.register_blueprint(threats.bp, url_prefix='/api/threats')

    logger.info('Heimdall sentinel API ready')
    return app


def _configure_logging(app: Flask) -> None:
    """Apply structured logging configuration from app config."""
    level = logging.DEBUG if app.config.get('DEBUG') else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s %(levelname)s %(name)s %(message)s',
    )
