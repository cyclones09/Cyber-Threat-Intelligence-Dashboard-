# OBSIDIAN — self-contained image (app + Tor in one container)
FROM python:3.11-slim

# Tor provides the SOCKS proxy used to reach .onion services in live mode.
RUN apt-get update \
    && apt-get install -y --no-install-recommends tor curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN chmod +x docker-entrypoint.sh

# Defaults — override via docker-compose or `docker run -e`.
ENV OBSIDIAN_TOR_PROXY=socks5h://127.0.0.1:9050 \
    OBSIDIAN_DEMO_MODE=true \
    OBSIDIAN_DATABASE=/data/obsidian.db

EXPOSE 8000
VOLUME ["/data"]

ENTRYPOINT ["./docker-entrypoint.sh"]
