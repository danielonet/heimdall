"""Shared Flask extension instances.

Kept separate from app.py so modules that need socketio (websocket.py,
sentinel/scheduler/) can import it without forming a circular import back
through the app factory.
"""
from flask_socketio import SocketIO

socketio = SocketIO(cors_allowed_origins='*', async_mode='threading')
