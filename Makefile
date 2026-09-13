# Build, test, and cross-compile the ServerOS daemon.
#
# Release builds are static musl binaries for linux/amd64 and linux/arm64.
# On macOS install cargo-zigbuild (`brew install zig && cargo install
# cargo-zigbuild`); on Linux the musl targets build natively with
# musl-tools installed.

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.0.0-dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
CHANNEL ?= dev
PUBKEY  ?=

PANEL_URL ?=
DOCS_URL ?=

export SERVEROS_VERSION=$(VERSION)
export SERVEROS_COMMIT=$(COMMIT)
export SERVEROS_CHANNEL=$(CHANNEL)
# Only export what is set: an empty value would override the built-in default.
ifneq ($(PUBKEY),)
export SERVEROS_RELEASE_PUBKEY=$(PUBKEY)
endif
ifneq ($(PANEL_URL),)
export SERVEROS_PANEL_URL=$(PANEL_URL)
endif
ifneq ($(DOCS_URL),)
export SERVEROS_DOCS_URL=$(DOCS_URL)
endif

TARGETS := x86_64-unknown-linux-musl aarch64-unknown-linux-musl

.PHONY: build test check clippy fmt release gateway linux-check messy-check clean

build:
	cargo build --workspace

test:
	cargo test --workspace

check:
	cargo check --workspace --all-targets

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

fmt:
	cargo fmt --all

## Static Linux binaries in dist/.
release:
	@mkdir -p dist
	@for t in $(TARGETS); do \
		echo "building $$t"; \
		SERVEROS_TARGET=$$t cargo zigbuild --release --target $$t -p serverosd || exit 1; \
		arch=$$(echo $$t | sed -e 's/x86_64.*/amd64/' -e 's/aarch64.*/arm64/'); \
		cp target/$$t/release/serverosd dist/serverosd-$(VERSION)-linux-$$arch; \
	done
	@cd dist && sha256sum serverosd-$(VERSION)-linux-* > SHA256SUMS && cat SHA256SUMS

## The gateway binary for the current host (release profile).
gateway:
	cargo build --release -p serveros-gateway
	@ls -l target/release/serveros-gateway

## Type-check for Linux from any host, using Docker.
linux-check:
	docker run --rm -v "$(PWD)":/src -v "$(HOME)/.cargo/registry":/usr/local/cargo/registry \
		-w /src -e CARGO_TARGET_DIR=/src/target-linux rust:1-bookworm \
		cargo check --workspace --all-targets

## Run the daemon's discovery against a deliberately messy Linux server
## (tests/fixtures/messy-server) and assert what it must find.
messy-check:
	scripts/messy-server.sh

clean:
	cargo clean
	rm -rf dist target-linux
