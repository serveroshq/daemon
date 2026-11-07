# A "machine" for the project-network end-to-end test: a Debian box with
# its own dockerd, the firewall tools, and clients to test with.
# wireguard-tools is deliberately NOT installed: the network job installs
# it, as it would on a fresh VPS.
FROM debian:bookworm
RUN apt-get update -q \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends \
      iproute2 iputils-ping kmod procps curl ca-certificates socat netcat-openbsd \
      docker.io iptables nftables ufw postgresql-client sqlite3 jq \
 && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
