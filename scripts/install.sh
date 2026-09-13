#!/usr/bin/env bash
# ServerOS daemon installer.
#
#   curl -fsSL https://serveros.com/install.sh | sudo bash -s -- --token=ENROL_TOKEN
#
# This script is short on purpose. Read it. It:
#   1. checks this is Linux with systemd, root, and a supported CPU
#   2. downloads the serverosd binary for this machine and verifies its
#      SHA-256 against the published checksum file
#   3. installs it to /usr/local/bin/serverosd
#   4. runs `serverosd enrol`, which does the rest and prints each step
#
# It does not touch any service, package, firewall rule, or file outside
# /usr/local/bin, /etc/serveros, /var/lib/serveros, /var/log/serveros and
# the serverosd systemd unit. Remove everything with `serverosd uninstall`.

set -euo pipefail

INSTALLER_VERSION="1"
PANEL="${SERVEROS_PANEL:-https://api.serveros.com}"
RELEASES="${SERVEROS_RELEASES:-https://releases.serveros.com}"
VERSION="${SERVEROS_VERSION:-latest}"
TOKEN=""
BIN=/usr/local/bin/serverosd

for arg in "$@"; do
  case "$arg" in
    --token=*) TOKEN="${arg#--token=}" ;;
    --panel=*) PANEL="${arg#--panel=}" ;;
    --version=*) VERSION="${arg#--version=}" ;;
    --help|-h)
      sed -n '2,15p' "$0"; exit 0 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

say()  { printf '  %s\n' "$*"; }
fail() { printf '\nerror: %s\n' "$*" >&2; exit 1; }

echo "ServerOS daemon installer (v$INSTALLER_VERSION)"
echo

[ "$(id -u)" -eq 0 ] || fail "run this as root (sudo). The daemon manages services, so it installs as root."
[ "$(uname -s)" = "Linux" ] || fail "the daemon runs on Linux only (this is $(uname -s))."
[ -d /run/systemd/system ] || fail "systemd was not found. The daemon needs systemd to stay running; other init systems are not supported yet."
[ -n "$TOKEN" ] || fail "no enrolment token. Copy the full command from the panel: it ends with --token=…"

case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) fail "unsupported CPU architecture $(uname -m); amd64 and arm64 are supported." ;;
esac

if [ -x "$BIN" ] && [ -f /etc/serveros/daemon.toml ]; then
  fail "ServerOS is already installed on this machine ($("$BIN" version 2>/dev/null || echo unknown)). Run 'serverosd disconnect --yes' first to enrol it again."
fi

command -v curl >/dev/null || fail "curl is required; install it and re-run."

if [ "$VERSION" = "latest" ]; then
  VERSION="$(curl -fsSL "$RELEASES/stable/VERSION" 2>/dev/null || true)"
  [ -n "$VERSION" ] || fail "could not read the latest version from $RELEASES (check outbound HTTPS on port 443)."
fi

ASSET="serverosd-${VERSION}-linux-${ARCH}"
URL="$RELEASES/${VERSION}/${ASSET}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

say "machine:  $(hostname) ($(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME" || echo Linux), $ARCH)"
say "version:  $VERSION"
say "download: $URL"
echo

curl -fsSL --retry 3 -o "$TMP/$ASSET" "$URL" \
  || fail "could not download $URL. Check outbound HTTPS (port 443) and DNS on this machine."
curl -fsSL --retry 3 -o "$TMP/SHA256SUMS" "$RELEASES/${VERSION}/SHA256SUMS" \
  || fail "could not download the checksum file for $VERSION."

EXPECTED="$(grep " ${ASSET}\$" "$TMP/SHA256SUMS" | awk '{print $1}')"
[ -n "$EXPECTED" ] || fail "no checksum published for $ASSET; refusing to install an unverifiable binary."
ACTUAL="$(sha256sum "$TMP/$ASSET" | awk '{print $1}')"
[ "$EXPECTED" = "$ACTUAL" ] || fail "checksum mismatch for $ASSET (expected $EXPECTED, got $ACTUAL). The download is corrupt or tampered with; nothing was installed."
say "checksum verified"

install -m 0755 "$TMP/$ASSET" "$BIN"
say "installed $BIN"
echo

exec "$BIN" enrol --token="$TOKEN" --panel="$PANEL"
