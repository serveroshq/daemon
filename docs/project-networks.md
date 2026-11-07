# Project networks, data copies and release ports

What the daemon does when the panel joins a project's machines over a
private network, copies a database from one machine to another over it,
and runs two copies of an app on one machine. Everything here is checked
by `make test`, and the network and copy paths end to end by
`make e2e-networks`.

## The `network` job

One job brings a project's network up on this machine, or takes it down.

```json
{
  "type": "network",
  "network": "p7k2q9",
  "action": "up",
  "address": "10.88.3.2/24",
  "listen_port": 51820,
  "peers": [
    { "public_key": "aGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd28=",
      "address": "10.88.3.3/32",
      "endpoint": "203.0.113.7:51820" }
  ],
  "expose": [
    { "port": 5432, "target": "127.0.0.1:5432" }
  ]
}
```

| Field | What it is |
| --- | --- |
| `network` | The project's network id: 1 to 12 lowercase letters and digits. |
| `action` | `up` or `down`. `down` needs only `network`. |
| `address` | This machine's address on the network, with its prefix. |
| `listen_port` | The UDP port WireGuard listens on. |
| `peers` | Every other machine on the network: its `public_key`, its `address`, and an `endpoint` (`host:port`) unless it can only dial in. |
| `expose` | Every port this machine offers on its network address, and the local service (`target`) each one goes to. |

`up` is declarative. It sets exactly what it's given and can be sent again
any time: peers that aren't listed are removed, listed ones keep their
sessions, and ports that aren't listed are closed. Sending the same `up`
twice changes nothing.

### What `up` checks

Everything is checked before anything on the machine is touched. A job
that fails a check fails in the `validate` phase and leaves nothing
behind.

- The address is IPv4 with a prefix from /8 to /30, inside 10.0.0.0/8,
  100.64.0.0/10 or 192.168.0.0/16, and isn't the network's own address or
  its broadcast address. 172.16.0.0/12 isn't allowed: Docker's bridges
  live there.
- `listen_port` is there and isn't 0.
- At most 250 peers. Each public key is 44 characters of standard base64
  that decode to 32 bytes, as `wg` prints them. Each peer address is one
  IPv4 address (`10.88.3.3` or `10.88.3.3/32`) on the network, not this
  machine's own. No key or address is listed twice. An endpoint is an IP
  address or a hostname, then a port.
- At most 64 exposed ports, none of them 0 and none twice. A target is
  `ip:port` on loopback (127.0.0.0/8) or the Docker bridge range
  (172.16.0.0/12), nothing else.

### What it makes

- `wireguard-tools`, if `wg` is missing, with apt, dnf or yum.
- A private key for the network, made on the machine the first time and
  kept in `/var/lib/serveros/networks/{network}.key` (0600, in a 0700
  folder). It is never sent anywhere; the job answers with the public key.
  The config `wg syncconf` reads holds the key, so it is written beside it
  and deleted straight after.
- A WireGuard interface named `sos{network}` (`sosp7k2q9`). Ids are at most
  12 characters so the name fits the kernel's 15. It gets the address and
  the peers; peers with an endpoint are kept alive every 25 seconds.
- A small TCP forwarder for each exposed port, listening on the network
  address and passing connections to the target. A database that only
  listens on 127.0.0.1 is reachable from the project this way and from
  nowhere else. The forwarder only takes connections from the network,
  from the machine itself, and from local containers whose address is on
  one of the machine's own `docker*` or `br-*` bridges.

### The firewall

The rules follow `[integrations] firewall` in `daemon.toml`. There are
three kinds: WireGuard's UDP port from anywhere, everything that arrives on
`sos{network}` from the network, and, for each exposed port, local
containers reaching the network address on that port over `docker*` or
`br-*` (not from the 172.16.0.0/12 range alone, since a provider or VPC
network can sit in it too).

- **ufw**: one `ufw allow` per rule. Rules a changed `up` no longer needs
  are deleted.
- **nftables**: the rules go in a chain of the network's own, `net_{id}`,
  in the `inet serveros` table, jumped to from its `input` chain (made only
  if it's missing, so an existing policy isn't reset). Since a drop in any
  input chain is final, the same rules also go at the top of every other
  inet table's input chain, tagged `serveros:net_{id}`, and come out by
  that tag. `ip` and `ip6` tables are left to iptables-nft.
- **iptables**: a chain `SOS-{id}`, jumped to from the top of `INPUT`.
- **none**: no rules.

If the backend changes between two `up`s, the old backend's rules come out
first.

### Results

`up` answers with what the panel needs to tell the other machines:

```json
{ "network": "p7k2q9", "interface": "sosp7k2q9",
  "public_key": "…", "address": "10.88.3.2/24", "listen_port": 51820 }
```

`down` answers `{"network": "p7k2q9", "removed": true}`. It stops the
forwarders, deletes the interface, takes out the firewall rules, deletes
the key and forgets the network. Taking down a network the machine doesn't
have succeeds too. A later `up` makes a new key.

### After a restart

WireGuard interfaces don't survive a reboot. The last `up` of each network,
and the firewall rules it made, are kept in `state.db`, and every stored
network is brought back up when the daemon starts, with the same key. Each
one is checked against the machine's policy first and written to
`actions.log` like any other change.

## Running a command in a container: `service_exec`

```json
{
  "type": "service_exec",
  "service": "docker:3f2a1c9e8b7d",
  "command": "pg_dump …",
  "timeout_secs": 3600,
  "env": { "SOURCE_HOST": "10.88.3.3", "SOURCE_PASSWORD": "…" }
}
```

The command runs as `docker exec <container> sh -c <command>` in the
service's container. The job answers `{"exit_code": N}`: a command that
exits non-zero still finishes the job, and the code says how it went. Its
output streams into the job's log.

`env` hands settings to the command by name, for things like the password
of the database a copy is made from. It is optional; panels that don't
send it get what they always did.

- Each setting goes to docker as `-e NAME`, never `-e NAME=value`. The value
  is in docker's own environment and docker passes it on, so it is never in
  an argument list and never in `ps`, on the machine or in the container,
  unless the command itself puts it on a command line.
- The job's log shows the command as written (`$ pg_dump -h "$SOURCE_HOST" …`),
  not with the values filled in.
- If the command prints a value anyway, it is replaced with `[redacted]` in
  the log, as deploy settings are (values of 8 characters or more).
- The job as `state.db` keeps it has each value replaced with `[redacted]`.
- Names are letters, digits and underscores, not starting with a digit, and
  not `PATH`, `HOME` or `LC_ALL`, which the daemon sets itself. A bad name
  fails the job before anything runs.

A command gets 60 seconds unless the job asks for more, and never more than
an hour (3600 seconds), long enough to copy a database between machines.
The job as a whole has its own limit (`timeout_secs` on the command, or
`limits.job_timeout_secs`, 30 minutes by default), so a long command needs
both.

### Copying a database

The panel uses both jobs to fill a copy of a database (a staging copy of
production, say) from the original on another machine. The original's
machine exposes the database's port on its network address. The panel then
runs the copy's dump-and-restore command inside the copy's own container on
the other machine, with the original's address, port, user, password and
database as `SOURCE_*` settings. The container reaches the network address
through its machine, over the project's WireGuard interface.

`make e2e-networks` does this on real machines for PostgreSQL 17 and MySQL
8.4, with the commands the panel sends, and checks that every row arrives,
that a second copy replaces the first rather than adding to it, that a
wrong password fails without touching the copy, that the original is
unchanged, that no password shows up in the job's log, `state.db` or `ps`,
and that a machine outside the network can't reach the original.

## Release ports

A deployed release listens on `127.0.0.1` on a port between 20000 and
29999, worked out from the app's name and the commit. Two apps at the same
commit on one machine, such as production and a staging copy of it, get
different ports. A release keeps the port it was given, so rollbacks go
back to the same one; only new releases are given a port this way.
