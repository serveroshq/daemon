#!/bin/sh
# Bring the mess up, run the daemon's read-only scan, and check the report.
set -eu

echo "== starting services"
service postgresql start >/dev/null
redis-server --daemonize yes --port 6379 --bind 127.0.0.1 >/dev/null
nginx
cron
# A pm2-managed app, the way a developer would have left it.
su -s /bin/sh -c "cd /srv/shop-api && pm2 start server.js --name shop-api >/dev/null 2>&1" root
# A game server in a screen session.
screen -dmS minecraft python3 -m http.server 25565 --bind 0.0.0.0
# Someone's nohup'd script.
nohup python3 -m http.server 8080 --bind 127.0.0.1 >/tmp/adhoc.log 2>&1 &
# The intruder's processes: one from /var/tmp (Docker's /dev/shm is noexec),
# one dressed as a kernel thread.
cp /bin/sleep /var/tmp/kdevtmpfsi && /var/tmp/kdevtmpfsi 600 &
bash -c 'exec -a "[kworker/0:1]" sleep 600' &
sleep 2

echo "== serverosd inventory"
/opt/serverosd inventory --json > /tmp/inventory.json
/opt/serverosd inventory | sed 's/^/   /'

echo "== checks"
python3 /check.py /tmp/inventory.json

echo "== serverosd audit"
/opt/serverosd audit --json > /tmp/audit.json
/opt/serverosd audit | sed 's/^/   /'

echo "== audit checks"
python3 /check_audit.py /tmp/audit.json
