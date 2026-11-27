# A "machine" for the deploy end-to-end test: a plain Debian box without
# Docker. The docker_install job installs it from Docker's repository, as
# it would on a fresh VPS; entrypoint.sh stands in for systemd and starts
# dockerd once it's there.
FROM debian:bookworm
RUN apt-get update -q \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends \
      ca-certificates curl git socat jq procps iproute2 iptables kmod \
 && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
