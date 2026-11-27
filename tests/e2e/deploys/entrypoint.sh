#!/bin/sh
# No systemd in here: this loop does its job for Docker, starting dockerd
# whenever it's installed and not running. /var/lib/docker and
# /var/lib/containerd are volumes, so overlayfs works inside the container.
# STORE=classic keeps images the pre-containerd way (Docker before 29, or
# upgraded from it).
if [ "${STORE:-containerd}" = classic ]; then
    mkdir -p /etc/docker
    echo '{"features":{"containerd-snapshotter":false}}' >/etc/docker/daemon.json
fi
(
    while true; do
        if command -v dockerd >/dev/null 2>&1 && ! pgrep -x dockerd >/dev/null 2>&1; then
            dockerd --log-level=warn >>/var/log/dockerd.log 2>&1 &
        fi
        sleep 1
    done
) &
if [ -x /opt/deploy-harness ]; then
    /opt/deploy-harness serve --socket /run/sosdeploy.sock >/var/log/harness.out 2>&1 &
fi
touch /run/machine-ready
exec sleep infinity
