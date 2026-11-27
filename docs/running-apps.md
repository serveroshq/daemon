# Running deployed apps

What the daemon does with a `deploy` job once the app's image is built:
how it starts the new release, checks it, moves traffic to it, and puts
things back when something fails. Rollbacks and Compose apps are here too.
Everything here is checked by `make test`; the container and Compose
paths also run against a real Docker with
`SERVEROS_LIVE_DOCKER=1 cargo test -p daemon-deploy --test deploy_live -- --ignored`.

These are the fields of a deploy that decide how the app runs. All of them
are optional.

```json
{
  "type": "deploy",
  "service": "shop",
  "commit": "4f2a9c...",
  "port": 3000,
  "env": { "APP_ENV": "production", "JWT_KEY": "-----BEGIN PRIVATE KEY-----\n..." },
  "health": { "path": "/up", "expected_status": 0, "timeout_secs": 10,
              "retries": 5, "start_period_secs": 60, "interval_secs": 3 },
  "volumes": [ { "name": "uploads", "path": "/var/www/storage" } ],
  "network": "serveros",
  "release_command": "php artisan migrate --force",
  "post_deploy_command": "php artisan queue:restart",
  "domains": ["shop.example.com"]
}
```

## The order of a deploy

1. **Wait** for any other deploy or rollback of the same app to finish.
   The log says it's waiting. Other apps aren't held up.
2. **Check** the settings that can't work (an env name docker won't take,
   a volume over `/`, a bad network name) before anything is fetched.
3. **Fetch and build** the image (see the build docs).
4. **Prepare**: work out the port, make the volumes and the network.
5. **Release command**, if there is one, in a throwaway container.
6. **Start** the new release beside the live one, on a port of its own.
7. **Health check** the new release.
8. **Proxy**: point the app's domains at the new release.
9. **Verify**: check it again, now that it's serving.
10. **Record** it as live. From here the deploy doesn't fail.
11. **Post-deploy command**, if there is one, inside the new container.
12. **Drain**: stop the old release after 5 seconds. It's kept, stopped,
    for a rollback. The last 5 releases are kept.

## Port

`port` is the port the app listens on inside its container. When it isn't
set, the daemon reads the image's `EXPOSE` and takes the lowest TCP port,
and without one it uses 80. The log says which, and the job's result has
it as `container_port`.

Unless the app's `env` sets `PORT` itself, the container gets
`PORT=<container port>`, so apps that read it listen where they're
checked.

Each release is published on `127.0.0.1` on a port from 20000 to 29999,
picked from the app's name and commit. When that port is taken (something
listens on it, or another ServerOS container, running or stopped, has it),
the next free one is used and the log says so.

## Settings

Every `env` value reaches the container exactly as sent, over several
lines too (PEM keys, JSON). Values are never on a command line: docker is
run with `-e NAME` and the value in its own environment. The few names the
docker client reads itself (`PATH`, `HOME`, `TMPDIR`, `DOCKER_*`,
`BUILDKIT_*` and the `*_PROXY` ones) go in a root-only env file instead,
and those have to be one line.

## Health check

`health` decides when a new release counts as up.

| Field | What it does |
| --- | --- |
| `path` | The page to ask for. |
| `expected_status` | The answer that counts. `200` also takes a redirect. `0` takes any answer below 500: the app is there and isn't failing. Missing means 200. |
| `timeout_secs` | How long one try waits for an answer. Missing means 30. |
| `start_period_secs` | Time the app gets to boot. Tries run every interval during it, and failures don't count. Missing means 0. |
| `retries` | Tries after the start period. Missing means 5. |
| `interval_secs` | Seconds between tries. Missing waits 2, 4, 8, then 16 seconds after each failure, and 2 during the start period. |

The request goes to the release's local port with `Host` set to the app's
first domain that isn't a wildcard (`localhost` when it has none), so apps
that only answer their own names (Django's `ALLOWED_HOSTS`) pass.

A failure says what the last try found:

- nothing is accepting connections on the port: the app isn't listening
  there, or listens on `127.0.0.1` instead of `0.0.0.0`;
- no answer within the timeout;
- the page answered with the wrong status, or a server error;
- the port answered, but not with HTTP.

If the container crashed, the failure says that too, and it carries the
container's last 40 log lines.

Without `health`, the daemon only checks that the container keeps running
for about 10 seconds (for bots and workers). When such an app has domains
and nothing answers on its port, the log warns that the site will show an
error.

The check is kept with the release, and a rollback to it uses the same
check. Releases recorded before this was kept get the old check: `GET /`
expecting 200.

## Volumes

Folders the image declares with `VOLUME` each get a named volume, the
same for every release, so a deploy never starts the app over empty.

`volumes` adds the app's own. Each is the Docker volume
`serveros-<service>-<name>`, labelled with the app. Names are lowercase
letters, digits, dots, dashes and underscores, up to 63. Paths are
absolute, can't be `/`, and can't be listed twice. Where an app's volume
and a `VOLUME` folder are the same path, the app's volume is mounted.

Volumes are mounted in every release and in the release command's
container, kept between deploys, and kept for rollbacks. A volume that's
labelled as another app's is refused. Removing the app removes them only
with `delete_data`.

## Network

With `network` set, the network is made if it's missing (a bridge,
labelled as ServerOS's) and the container joins it with the service's
name as its address there, so apps on one machine reach each other by
name: `http://shop-api:3000`.

The container is created on Docker's default bridge first and joins the
shared network after, so it keeps an address on `docker0`. Services on the
machine that only let in Docker's bridge (a database whose `pg_hba.conf`
allows `172.17.0.0/16`) still let it in. Every container also gets
`host.docker.internal`, which points at the machine.

A rollback makes the network again if it was removed, and the release
rejoins it.

## Logs

An app's container keeps its logs to 3 files of 10 MB, unless the
machine's Docker sets a log driver or log options of its own in
`/etc/docker/daemon.json`; then Docker's choice stands.

## Release and post-deploy commands

`release_command` runs once per deploy, after the build and before the new
release starts, as `sh -c <command>` in a throwaway container of the new
image, with the app's settings, volumes and network but no port and no
name on the network. Its output is in the deploy's log. If it exits with
anything but 0, or is still running when the deploy runs out of time, the
deploy fails with the end of its output, and the live release keeps
serving. Use it for migrations.

`post_deploy_command` runs inside the new container (`docker exec`,
`sh -c`) once it's live. If it fails, the log has a warning and the deploy
still succeeds.

Images without `sh` can't run either; the failure says so.

## When a deploy fails

The daemon puts back what it changed, then says what's serving:

- The new release's container is removed.
- If the proxy had already moved to the new release (the verify step
  failed), it's pointed back at the release that was live, or the site is
  taken down when there was none.
- The release is marked failed, unless it's the live commit deployed
  again, which is still serving.
- The job's workspace is removed.

The last line of the log is true: "shop is still live on release 4f2a9c1"
only when that release's container is running and the proxy points at it.

A proxy reload that fails leaves the proxy serving what it had, and the
site's file goes back to match, so the next reload doesn't pick it up.

## Time

A deploy gives itself the job's timeout less a fifth of it (at most two
minutes less), and stops on its own when that runs out, with the last
lines of its log in the failure and time left to put things back. If
the new release was already live by then, the deploy succeeds and the log
says the tidying after it ran out of time.

Workspaces left in `jobs/` by deploys that never finished (the daemon was
stopped partway) are removed when the daemon starts, once a day old.

## Compose apps

A Compose deploy moves the live stack's files and settings aside before
the new ones go in. If the deploy fails, they're put back and the stack is
brought up from them again, and the log says whether that worked.

With `port` (the host port the stack publishes), the port is health
checked: with the app's `health`, or by default `GET /` taking any answer
below 500, with 30 seconds to start. Without a port, every container of
the stack has to keep running for about 10 seconds; one that exits 0 (a
setup step) is fine, one that exits with an error, keeps restarting or
never starts fails the deploy with its logs.

The env file Compose reads for `${NAME}` keeps every value exactly, `$`
and quotes and line breaks included.

`limits`, `release_command`, `post_deploy_command`, `volumes` and
`network` apply to single-container apps; for a Compose app the log says
to set them in its Compose file.

Compose apps roll back by deploying the earlier commit again.

## Redaction

Deploy logs hide settings that look secret and leave the rest readable:

- A setting whose name has `KEY`, `TOKEN`, `SECRET`, `PASS`, `PWD`, `AUTH`,
  `CREDENTIAL`, `PRIVATE`, `DSN` or `CERT` in it is hidden from 4
  characters, and so is any URL with a password in it.
- Any other setting is hidden from 12 characters, unless it's plainly
  harmless: a word, a number, a yes or no, a host name, a path, or a URL
  without credentials or a token in it.
- A value over several lines is hidden line by line.
- Build settings (`build.args`) follow the same rules, and the repository
  token and registry passwords are always hidden.

So `APP_ENV=production` and `APP_URL=https://shop.example.com` read as
themselves, and a token under any name doesn't. The job as state.db keeps
it has every setting's value removed.

The live log reaches the panel in order and whole: when the link to the
panel is behind, lines wait for the next update instead of being dropped.
