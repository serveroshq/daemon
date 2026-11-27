# Deploys: how an app's image is made

What the daemon does with a `deploy` job's `build` settings, and the two
jobs that help the panel set an app up: `repo_inspect`, which reads a
repository without building it, and `docker_install`, which puts Docker on
a machine. Everything here is checked by `make test`, and end to end, on a
fresh machine in Docker, by `make e2e-deploys`.

## Build methods

`build.method` says how the release's image is made. A deploy without
`build` builds the repository's Dockerfile, or runs its `compose_file`, as
daemons always have.

| Method | What happens |
| --- | --- |
| `dockerfile` | `docker build` with the repository's Dockerfile (`dockerfile`, relative to `base_dir`). |
| `railpack` | [Railpack](https://railpack.com) reads the app's files (package.json, requirements.txt, go.mod, composer.json, index.html…), works out how to install, build and start it, and BuildKit builds that plan. For apps with no Dockerfile. |
| `image` | `docker pull build.image` with the job's `registries`. Nothing is fetched or built, and `repo` can be empty. |

A deploy with `compose_file` runs Compose whatever `build` says; asking for
`railpack` or `image` with a Compose file fails before anything is touched.

Every method ends with the image tagged `serveros/<app>:<commit>`, so
starting, health checks, releases and rollback work the same for all of
them. An `image` deploy still needs a `commit` (7 to 64 hex characters) to
name its release: an id the panel makes, like a hash of the image and the
deploy.

The result says which it was, as `build_method` (`dockerfile`, `railpack`,
`image` or `compose`).

### `build` fields

| Field | What it is |
| --- | --- |
| `method` | `dockerfile` (the default), `railpack` or `image`. |
| `image` | For `image`: what to run, like `ghcr.io/acme/api:1.4` or `name@sha256:…`. |
| `target` | For `dockerfile`: the stage to build (`--target`). |
| `args` | Settings the build can read, by name: a Dockerfile's `ARG`s, or Railpack's build environment. Not given to the running app unless they're also in `env`. |
| `install_command`, `build_command`, `start_command` | For `railpack`: commands that replace the ones it works out. |
| `no_cache` | Build from scratch: no layer cache, and no reusing an image already built from the same files. |
| `submodules` | Fetch the repository's submodules, recursively and shallow. Default true. |
| `lfs` | Fetch Git LFS files, when the repository's `.gitattributes` uses LFS. Default true. |

### Build settings stay secret

A setting's value is never on a command line, in `systemctl show`, in the
job's log or in state.db:

- Dockerfile builds pass `--build-arg NAME` with no value, and docker reads
  the value from its own environment.
- Railpack gets `railpack prepare --env NAME` the same way, and BuildKit
  gets each one as a secret, `--secret id=NAME,env=NAME`, so it's mounted
  for the steps that use it and kept out of the image. A hash of the values
  (`secrets-hash`) rebuilds the layers that read one when it changes.
- The values are scrubbed from the job's log and from the job kept in
  state.db, like `env`.

Names the build tools use themselves (`PATH`, `HOME`, `TMPDIR`, and any
starting `DOCKER_`, `BUILDKIT_`, `BUILDX_` or `SERVEROS_`) are left out of
the build, and the log says so. A Dockerfile `ARG`'s value is kept in the
image's history, as Docker does with every build argument; for a token a
build needs and the image mustn't keep, use Railpack, or a BuildKit secret
mount in the Dockerfile.

### Using the same image again

An image built from the same files (the repository, commit, Dockerfile,
job files, folder and build settings) is used as it is when the same commit
is deployed again, for a settings change say. `no_cache` builds again
anyway. Dockerfile images carry the fingerprint as a label; Railpack's
frontend doesn't take labels, so the daemon keeps its last one per app in
state.db. Images built before build settings keep their fingerprint while
the deploy's `build` is the default one.

## Railpack

The daemon runs Railpack **0.44.0**, downloaded the first time an app needs
it to `/var/lib/serveros/bin/railpack-0.44.0` from its GitHub release, and
checked against the sha256 pinned in the daemon before it's used:

| Machine | Archive | sha256 |
| --- | --- | --- |
| amd64 | `railpack-v0.44.0-x86_64-unknown-linux-musl.tar.gz` | `50b55b6762321c4eb2a2b8850ea0ffcb70b3250f1a2b15519b4901b17ce09411` |
| arm64 | `railpack-v0.44.0-arm64-unknown-linux-musl.tar.gz` | `8f0d88077cf903faeaa463db192221900609f5d7c89d9430d9c3a0800479d18f` |

BuildKit builds the plan with Railpack's frontend at the same release,
pinned by digest:
`ghcr.io/railwayapp/railpack-frontend:v0.44.0@sha256:ca7b4f62a572e1910cf51dc181bd5b51111a07efe6604f80536e16a9923ffae2`.

A build goes:

1. `railpack prepare <app folder> --plan-out … --info-out …
   --error-missing-start`, with the build settings by name, `--build-cmd`
   and `--start-cmd` when given, and `RAILPACK_INSTALL_CMD` for an install
   command. The plan is written outside the app's folder and removed after.
2. The log says what Railpack found: the kind of app, the versions it
   picked, the start command, a static site's folder, and its warnings.
3. `docker buildx build --load` with `BUILDKIT_SYNTAX` set to the frontend,
   `cache-key=serveros-<app>` (so each app keeps its own package caches),
   the settings as secrets, and `--no-cache` for `no_cache`.

Docker 29 and later keeps images in containerd, and its own BuildKit runs
the build. Docker keeping images the older way can't run Railpack's merge
steps, so the build runs in a BuildKit container instead, the
`serveros-railpack` buildx builder, made the first time it's needed (its
state is in `/var/lib/serveros/buildx`, apart from anyone's own builders).

Static sites (an `index.html`, or a `public` folder) and single-page apps
built with Vite, Create React App, Angular and the like are served by Caddy
on `$PORT`, as Railpack sets them up.

When Railpack can't tell what the app is, the deploy fails with "Railpack
couldn't tell how to build this app" and says to add a Dockerfile or set a
start command; when it can't tell how to start it, it says to set a start
command.

## Before building

Before anything is fetched, the daemon checks the machine has what the
deploy needs, and fails with what to do when it hasn't:

| Missing | Failure | Next step |
| --- | --- | --- |
| `docker` | Docker isn't installed on this machine | Install Docker from the machine's page in ServerOS. |
| dockerd | Docker is installed but isn't running | Start it with `systemctl start docker`, or install it again. |
| Compose, for a Compose app | Docker Compose isn't installed on this machine | Install Docker from the machine's page (it comes with Compose). |
| buildx, for Railpack | … needs Docker's buildx plugin … | Install Docker from the machine's page, or add a Dockerfile. |
| under 2 GB free where Docker keeps images, or in the jobs folder | only 1.4 GB is free on the disk … | Remove unused images, or resize the disk. |

A failed build names the step that broke and what it printed, from
BuildKit's plain output (`docker build failed at [3/4] RUN npm ci (exit
code 254)`, then "It printed: …"), or the classic builder's `Step 7/12`.
When Docker Hub refuses a pull for going over its limit, a Dockerfile build
is tried once more without `--pull`, using the base images already on the
machine; if that fails too, the failure says it was Docker Hub's limit and
to add a Docker Hub login or wait. Running out of disk mid-build says so.

## Fetching

Deploys fetch the one commit, shallow, as before. Then:

- **Submodules**, when the repository has a `.gitmodules` and `submodules`
  is on: `git submodule update --init --recursive --depth 1`, with the same
  deploy key or token as the repository (a token only goes to the
  repository's own host).
- **Git LFS**, when a `.gitattributes` in the checkout says `filter=lfs` and
  `lfs` is on: `git lfs pull`. A machine without git-lfs gets it from its
  package manager (apt, dnf, yum or apk), as the reverse proxies are
  installed; if that fails, the deploy says to install it or turn LFS off.

Everything git is given (the key, the token as an auth header) goes through
its environment, never into `.git/config` or a URL. `resolve_ref` now takes
the `repo_token` too, so a private HTTPS repository's branches resolve. A
refused fetch says what opens that kind of address: the deploy key for an
SSH address, connecting the git host (or the SSH address) for an HTTPS one.

## The `repo_inspect` job

A repository's files at a commit, without building anything, so the panel
can tell what kind of app it is on any git host. Read-only: allowed in
read-only mode, gated as `deploy.inspect`.

```json
{
  "type": "repo_inspect",
  "service": "web",
  "repo": "git@gitlab.com:acme/shop.git",
  "ref": "main",
  "base_dir": "apps/web",
  "repo_token": "…"
}
```

Only `repo` is needed. An SSH address uses `service`'s deploy key, an HTTPS
one is read as public or with `repo_token`, and a missing `ref` means the
default branch. The daemon asks the repository for the commit, fetches just
that commit into a folder of the job's own, without a checkout and leaving
out files over 64 KB where the server allows it (a plain shallow fetch where
it doesn't), reads git's tree, and removes the folder. It gives up after a
minute.

```json
{
  "commit": "4f2a9c…",
  "ref": "main",
  "default_branch": "main",
  "files": ["package.json", "src/index.ts", "apps/web/package.json"],
  "contents": { "package.json": "{…}", "Dockerfile": "FROM node:22…" },
  "truncated": false
}
```

`files` are relative to `base_dir` (or the root), up to three folders deep,
at most 2000; `truncated` says there were more. `contents` holds up to 40
small text files (64 KB each at most) from that folder that say how an app
is built: package.json, composer.json, requirements.txt, pyproject.toml,
Pipfile, Gemfile, go.mod, Cargo.toml, mix.exs, pom.xml, build.gradle(.kts),
deno.json(c), Procfile, Dockerfile, `*.Dockerfile` and `Dockerfile.*`,
compose.y(a)ml, docker-compose.y(a)ml, .env.example, .env.sample,
.env.template, .env.dist, railpack.json, nixpacks.toml, .nvmrc,
.node-version, .python-version, runtime.txt, .tool-versions, index.html and
next, vite, nuxt, astro and svelte configs.

## The `docker_install` job

```json
{ "type": "docker_install" }
```

Installs Docker Engine with its Compose and Buildx plugins (`docker-ce
docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin`)
from Docker's own package repository, as docs.docker.com sets it up: apt on
Debian, Ubuntu and their derivatives (Mint, Pop!_OS, Raspberry Pi OS), dnf
on Fedora, RHEL, CentOS Stream, Rocky, Alma and Oracle Linux. A machine
that already lists Docker's repository keeps its own entry. Then it starts
Docker (`systemctl enable --now docker`) and checks `docker version`.

When Docker already runs with both plugins it changes nothing; when it runs
without one, only the missing plugin is added. Any other system is refused
with a pointer to Docker's install docs. Needs a confirmed instruction,
refused in read-only mode, gated as `docker.install`.

```json
{ "version": "29.1.2", "installed": true }
```

Afterwards the daemon looks at the machine again straight away, so the
panel sees Docker without waiting for the next scan.
