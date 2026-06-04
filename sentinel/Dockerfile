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

COPY . .

CMD ["gunicorn", \
     "--worker-class", "geventwebsocket.gunicorn.workers.GeventWebSocketWorker", \
     "--workers", "1", \
     "--bind", "0.0.0.0:5000", \
     "sentinel.api.app:create_app()"]
