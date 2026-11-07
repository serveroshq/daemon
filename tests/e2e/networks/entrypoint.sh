#!/bin/sh
# Start this machine's own dockerd, then idle. /var/lib/docker is a volume,
# so overlay2 works inside the container.
set -e
dockerd --log-level=warn >/var/log/dockerd.log 2>&1 &
for _ in $(seq 60); do
    docker info >/dev/null 2>&1 && break
    sleep 1
done
docker info >/dev/null 2>&1 || { echo "dockerd did not start" >&2; cat /var/log/dockerd.log >&2; exit 1; }
touch /run/machine-ready
exec sleep infinity
