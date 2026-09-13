# A deliberately untidy Linux server, the kind an importer meets in the
# wild: nginx in front of a pm2 app, postgres and redis started by hand, a
# game server in a screen session, a nohup'd script, and a cron job.
# No systemd (this is a container), which is itself one of the messy cases.
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        nginx postgresql redis-server nodejs npm screen python3 procps cron \
        ca-certificates openssl \
    && npm install -g pm2@5 \
    && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
COPY check.py /check.py
COPY shop-api.js /srv/shop-api/server.js
COPY shop.nginx /etc/nginx/sites-enabled/shop
RUN chmod +x /entrypoint.sh \
    && rm -f /etc/nginx/sites-enabled/default \
    && printf '*/5 * * * * root /usr/local/bin/backup.sh >> /var/log/backup.log 2>&1\n' > /etc/cron.d/backup \
    && printf '#!/bin/sh\necho backup\n' > /usr/local/bin/backup.sh && chmod +x /usr/local/bin/backup.sh \
    && mkdir -p /etc/letsencrypt/live/shop.example.com \
    && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 30 \
        -subj "/CN=shop.example.com" -addext "subjectAltName=DNS:shop.example.com" \
        -keyout /etc/letsencrypt/live/shop.example.com/privkey.pem \
        -out /etc/letsencrypt/live/shop.example.com/fullchain.pem 2>/dev/null

ENTRYPOINT ["/entrypoint.sh"]
