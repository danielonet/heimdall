"""Shared Flask extension instances.

Kept separate from app.py so modules that need socketio (websocket.py,
sentinel/scheduler/) or jwt_manager (routes/auth.py) can import them without
forming a circular import back through the app factory.
"""
from flask_jwt_extended import JWTManager
from flask_socketio import SocketIO

socketio = SocketIO(cors_allowed_origins='*', async_mode='threading')
jwt_manager = JWTManager()
