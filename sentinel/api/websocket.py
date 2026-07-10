"""WebSocket emit helpers for the /sentinel namespace."""
from sentinel.api.extensions import socketio


def emit_alert(alert: dict) -> None:
    """Emit a new alert event to all subscribers."""
    socketio.emit('alert:new', alert, namespace='/sentinel')


def emit_device_update(device: dict) -> None:
    """Emit a device snapshot refresh (fires every poll cycle)."""
    socketio.emit('device:update', device, namespace='/sentinel')


def emit_device_joined(device: dict) -> None:
    """Emit when a new device is seen for the first time."""
    socketio.emit('device:joined', device, namespace='/sentinel')


def emit_port_update(port: dict) -> None:
    """Emit updated PHY port stats."""
    socketio.emit('port:update', port, namespace='/sentinel')


def emit_wan_status(status: str) -> None:
    """Emit a WAN state-change event."""
    socketio.emit('wan:status', {'status': status}, namespace='/sentinel')


def emit_feed_refresh(feed_name: str, timestamp: str) -> None:
    """Emit when a threat intelligence feed is successfully refreshed."""
    socketio.emit('feed:refresh', {'feed': feed_name, 'timestamp': timestamp}, namespace='/sentinel')


def emit_ml_trained(mac: str, samples: int) -> None:
    """Emit when an ML model is retrained for a device."""
    socketio.emit('ml:trained', {'mac': mac, 'samples': samples}, namespace='/sentinel')
