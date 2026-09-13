# Fixtures

## messy-server

`make messy-check` builds `serverosd` for Linux inside Docker and runs
`serverosd inventory --json` on a container that looks like a server
someone has been hand-tending for a year:

| What                                  | How it was started            | Must be found as            |
|---------------------------------------|-------------------------------|-----------------------------|
| nginx on 80/443 for shop.example.com  | `nginx`                       | web server, ports 80/443    |
| pm2 app `shop-api` on 3000            | `pm2 start server.js`         | app, manager `pm2`          |
| postgres on 5432                      | `service postgresql start`    | database                    |
| redis on 6379                         | `redis-server --daemonize`    | cache                       |
| a "game server" on 25565              | `screen -dmS minecraft …`     | manager `screen`            |
| an ad-hoc python server on 8080       | `nohup python3 -m http.server`| a service or unknown listener|
| `/etc/cron.d/backup`                  | cron                          | scheduled task              |
| a letsencrypt-style certificate       | files under /etc/letsencrypt  | certificate with names      |

`check.py` fails the run if any row is missing or misclassified.

## What still needs a VM

Containers have no systemd and no Docker socket, so two importer paths run
only in their "not available" branch here: systemd unit discovery
(`daemon-inventory/src/systemd.rs`) and container discovery
(`daemon-inventory/src/docker.rs`). The section 16 chaos cases from the
spec (disk full mid-job, kill -9 during deploy, network partition during
update, clock skew) also need a disposable VM. A Multipass or Lima Ubuntu
box with `serverosd` installed from `dist/` is the intended target; the
job-level rollback and update rollback logic is unit-tested, but those
runs are the proof.
