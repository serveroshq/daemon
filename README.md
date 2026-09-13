# ServerOS daemon

`serverosd` is the one thing ServerOS installs on a machine: a single static
binary that connects out to the panel, discovers what is already running,
adopts it without a restart, and does the deploying, backing up, and
watching on the panel's behalf.

It runs as root, because updating packages, editing firewall rules, and
driving systemd and Docker need root. It is not a remote shell: everything
it can do is a fixed, reviewed list in `crates/daemon-capability`, every
privileged action is written to `/var/log/serveros/actions.log` in plain
English before it happens, and the things it will never do (read
`/etc/shadow`, read SSH private keys, leave permitted directories, phone
anywhere but the panel and configured storage) are tests, not prose.

## Install

```
curl -fsSL https://serveros.com/install.sh | sudo bash -s -- --token=ENROL_TOKEN
```

The script downloads the binary, verifies its checksum, and runs
`serverosd enrol`, which prints every step. There is no inbound port: the
daemon dials the panel over TLS 1.3 on 443 with a certificate issued at
enrolment, and reconnects on its own.

```
serverosd status        what the daemon is doing
serverosd inventory     a read-only scan of what is running here
serverosd doctor        checks, each with a fix
serverosd update        check for a release, or --to X to install one
serverosd disconnect    stop management; leave every service running
serverosd uninstall     remove ServerOS and print what went and what stayed
```

## Layout

One Cargo workspace, one crate per concern. Each crate's `lib.rs` says what
it is for; parsers are pure functions tested against fixtures so the suite
runs on any platform, and only the thin readers touch `/proc`, systemd, or
the Docker socket.

| Crate | What it owns |
| --- | --- |
| `daemon-core` | Paths, `daemon.toml`, build info, secret redaction |
| `daemon-protocol` | The versioned wire protocol; one driver per major |
| `daemon-audit` | `actions.log` |
| `daemon-capability` | The privileged operation set and the broker that gates it |
| `daemon-http` | The small HTTPS client for enrolment and release downloads |
| `daemon-state` | `state.db`: job ledger, telemetry ring buffer, outbox |
| `daemon-identity` | Keypair, CSR, client certificate, enrolment |
| `daemon-transport` | The outbound mTLS control channel, heartbeat, reconnect |
| `daemon-telemetry` | Machine facts, procfs samples, derived signals |
| `daemon-inventory` | Discovery: listeners, systemd, Docker, web servers, cron, TLS |
| `daemon-import` | Enrichment, honest previews, adoption, un-adoption |
| `daemon-services` | The adoption ledger and the systemd and Docker adapters |
| `daemon-jobs` | Durable, idempotent jobs with timeouts and streamed output |
| `daemon-files` | Symlink-safe file operations inside permitted roots |
| `daemon-streams` | Log tails and PTY sessions |
| `daemon-deploy` | Fetch by commit, build, health, Caddy swap, rollback |
| `daemon-backup` | Native dumps and tar, retention, pre-restore snapshots, S3 |
| `daemon-supervisor` | Self-health and the resource budget |
| `daemon-selfupdate` | Signed, policy-gated updates with automatic rollback |
| `daemon-uninstall` | The manifest of what ServerOS created, and its removal |
| `serverosd` | The binary: CLI, control loop, job handler, workers |
| `release-tool` | Key generation, signing, and manifests for CI |

## Building

```
make build          # debug build
make test           # the whole suite
make clippy         # lints, warnings denied
make linux-check    # type-check for Linux from macOS via Docker
make release        # static musl binaries in dist/ (needs cargo-zigbuild on macOS)
```

Release builds stamp the version, commit, channel, and the release public
key through environment variables (`SERVEROS_VERSION`, `SERVEROS_COMMIT`,
`SERVEROS_CHANNEL`, `SERVEROS_RELEASE_PUBKEY`). A binary built without a
public key cannot install updates, which is the safe failure.

## Gateway

`serveros-gateway` (`crates/serveros-gateway`) is the panel-side end of the
control channel. It terminates each daemon's mutual-TLS WebSocket, reads
the certificate serial, asks the panel (`POST /api/gateway/hello`) which
machine that is, and then relays: daemon envelopes are batched to
`/api/gateway/machines/{uid}/ingest`, and the panel pushes commands
through the gateway's loopback API (`POST /machines/{uid}/commands`).
Browser terminals and log tails attach to `/streams/{session}` with a
ticket the panel signed, so PTY bytes never pass through PHP.

```
php artisan daemon:ca init                      # once, in the panel
php artisan daemon:ca issue-server --host gateway.example.com --out /etc/serveros/gateway
make gateway && cp target/release/serveros-gateway /usr/local/bin/
cp deploy/gateway.env.example /etc/serveros/gateway.env   # fill in GATEWAY_SECRET
cp deploy/serveros-gateway.service /etc/systemd/system/ && systemctl enable --now serveros-gateway
```

It keeps no state: restart it and daemons reconnect with backoff.

## Integrations

The daemon drives host tools it does not replace. The defaults are what
the installer would pick on a fresh Ubuntu box; an existing server keeps
what it has by changing `[integrations]` in `/etc/serveros/daemon.toml`:

```toml
[integrations]
proxy = "caddy"      # caddy | nginx | none
firewall = "ufw"     # ufw | nftables | iptables | none
```

- **Proxy**: one site file per deployed service in a directory ServerOS
  owns (`/etc/caddy/serveros.d` or `/etc/nginx/serveros.d`), validated
  before reload, reverted if validation fails. Caddy handles TLS itself;
  with nginx, TLS stays whatever certbot or the operator set up.
- **Firewall**: ufw rules pass through verbatim. nftables and iptables
  take the port form (`22/tcp`, `from 10.0.0.0/8 to any port 5432`);
  nftables rules live in a table ServerOS owns (`inet serveros`).
- **Links**: the default panel (`SERVEROS_PANEL_URL`) and the docs base
  (`SERVEROS_DOCS_URL`) are build-time environment variables, and the
  release download allowlist is `[updates] allowed_hosts`.

## Fixtures

`make messy-check` builds the daemon for Linux in Docker and runs its
discovery scan against `tests/fixtures/messy-server`: nginx in front of a
pm2 app, postgres and redis started by hand, a game server in `screen`, a
`nohup`'d script, a cron job, and a letsencrypt-style certificate. The
checks assert each is found, classified, and attributed to the right
manager. Two things still need a real VM rather than a container: systemd
unit discovery (containers have no systemd, so only the honest "not
reachable" path runs) and the Docker socket.

## Updates

Automatic updates follow `daemon.toml`: they can be turned off, pinned to a
version, restricted to a channel, or limited to a maintenance window. A
major version change always waits for a person to approve it. Releases
carry `min_from`, so a daemon too far behind is told to step through an
intermediate release. The old binary stays beside the new one, and a new
binary that fails to reconnect three times is rolled back automatically.

## Protocol

Every message is an envelope with a protocol major, a monotonic sequence
number, an id, and a typed payload. Changes within a major are additive;
a breaking change is a new driver in `daemon-protocol`, and the old driver
keeps shipping until no supported daemon speaks it. The panel side needs:

- `POST /api/daemon/enrol` — token + CSR → machine id, certificate, CA
- `wss://<host>/daemon/control` — the mTLS control channel
- `GET /api/daemon/releases/latest?channel=&arch=` — the release manifest

## Licence

Business Source License 1.1.
