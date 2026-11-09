# Contributing to the ServerOS daemon

Thanks for wanting to help. `serverosd` runs as root on servers people care about, so the bar for changes here is high. This page explains how to get a change in without wasting your time.

## Before you write code

- **Small fixes** (typos, docs, an obvious bug with a clear fix, a new fixture for a parser): just open a pull request.
- **Anything bigger**: open an [issue](https://github.com/serveroshq/daemon/issues/new/choose) first and wait for a maintainer to agree on the approach.
- **Always an issue first** for anything that changes what the daemon is allowed to do: a new or wider capability in `crates/daemon-capability`, new paths it can touch, new network destinations, new commands it runs, or changes to self-update, enrolment, certificates or the protocol.
- **Security problems**: never in public. Email [security@serveros.com](mailto:security@serveros.com) or use [private reporting](https://github.com/serveroshq/daemon/security/advisories/new).

## Rules the daemon keeps

These are tests, not just promises, and pull requests that weaken them won't be merged:

- Everything it can do is a fixed, reviewed list in `crates/daemon-capability`. It is not a remote shell.
- Every privileged action is written to `/var/log/serveros/actions.log` in plain English before it happens.
- It never reads `/etc/shadow` or SSH private keys, never leaves permitted directories, and never connects anywhere but the panel and configured storage.
- Secrets never end up in logs, job output, error reports or state.

## Building and testing

You need a recent stable Rust. On macOS, Linux-only code is checked through Docker.

```
make build          # debug build
make test           # the whole suite
make clippy         # lints, warnings denied
make fmt            # format
make linux-check    # type-check for Linux from macOS via Docker
make messy-check    # discovery against a deliberately messy server
make e2e-networks   # project networks end to end, in Docker
```

Before you push, `cargo fmt --all -- --check`, `make clippy` and `make test` should pass. CI also runs the tests as root and builds static musl binaries for amd64 and arm64.

Parsers are pure functions tested against fixtures in `tests/fixtures`, so add a fixture for whatever real-world output you're handling.

## The CLA

The first time you open a pull request, a bot asks you to sign our [Contributor License Agreement](https://github.com/serveroshq/panel/blob/main/CLA.md) by posting a comment. You only do this once, and it covers every ServerOS repo. You keep the copyright in your work.

## Pull requests

- One change per pull request, focused and small, ideally under 500 changed lines.
- No more than 3 open pull requests at a time, please.
- Fill in the template: what changed, why, and how you tested it.
- Add or update tests, including the "never does" tests if you touch anything near them.
- If you're new here, a maintainer has to start CI on your pull request.

A maintainer has to approve every pull request, new pushes reset the approval, conversations have to be resolved, and we squash-merge.

## Using AI tools

You can, but you're responsible for every line. Read the [AI policy](https://github.com/serveroshq/panel/blob/main/AI_POLICY.md); it applies here too.

## Code of Conduct

Everyone taking part agrees to our [Code of Conduct](https://github.com/serveroshq/.github/blob/main/CODE_OF_CONDUCT.md).
