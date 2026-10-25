FROM python:3.12-slim

# System packages required by Scapy (libpcap), Nmap, and network tools
RUN apt-get update && apt-get install -y \
    nmap \
    libpcap-dev \
    net-tools \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# docker-compose builds this image with context ./sentinel (this directory),
# so copying straight to WORKDIR would put api/, config.py, etc. directly
# under /app with no "sentinel" package directory anywhere — every internal
# absolute import (e.g. `from sentinel.api.extensions import ...`) and the
# CMD's own `sentinel.api.app:create_app()` entry point would fail with
# ModuleNotFoundError. Nesting one level under /app/sentinel/ makes the
# package importable the way the code already assumes.
COPY . ./sentinel/

# gthread, not gevent: Flask-SocketIO is configured with async_mode='threading'
# (sentinel/api/extensions.py), which needs a real-OS-thread WSGI worker.
# gevent's monkey-patched threads are greenlets cooperatively scheduled on a
# single OS thread, which don't give SentinelScheduler's background asyncio
# loop a genuinely separate thread — it crashed at startup under gevent
# ("Cannot run the event loop while another loop is running"). --workers 1
# stays fixed: the scheduler must run exactly once per process, and gunicorn
# worker processes don't share Python state, so >1 worker would each start
# its own competing scheduler/poll loop.
# Apply Alembic migrations first (retrying while Postgres comes up), then
# exec gunicorn so it is PID 1 and receives stop signals. See
# sentinel/db/migrate.py for why this isn't just `alembic upgrade head`.
CMD ["sh", "-c", "python -m sentinel.db.migrate && exec gunicorn --worker-class gthread --threads 4 --workers 1 --bind 0.0.0.0:5000 'sentinel.api.app:create_app()'"]
