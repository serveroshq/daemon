#!/usr/bin/env bash
# End-to-end test for deploys: real Docker installed by the docker_install
# job, real builds (a Dockerfile, Railpack for apps without one, a prebuilt
# image), real containers answering HTTP, in a container standing in for a
# fresh machine.
#
#   make e2e-deploys                  Docker keeping images in containerd
#   STORE=classic make e2e-deploys    the pre-containerd image store, where
#                                     Railpack builds in a BuildKit container
#
# The "machine" is a privileged Debian container with no Docker at first.
# On it runs the deploy-harness example (crates/daemon-deploy/examples):
# the same Deployer, job runner and secret scrubbing serverosd uses for
# deploy, repo_inspect, docker_install and resolve_ref jobs, behind a unix
# socket (serverosd itself needs an enrolled panel). Jobs are sent as the
# panel sends them, for git repositories made on the machine from
# tests/e2e/deploys/fixtures.
#
# Needs: docker, jq, and network access from the machine: Docker's apt
# repository, Docker Hub, ghcr.io (Railpack's images), github.com (the
# Railpack binary), and npm, PyPI and Node/Python downloads for the builds.
# Everything it creates is removed when it exits.
set -uo pipefail

cd "$(dirname "$0")/../../.."
ROOT=$PWD
HERE=tests/e2e/deploys
OUT=$ROOT/target-linux/e2e-deploys
STORE=${STORE:-containerd}
PREFIX=e2e-deploy
M=$PREFIX-machine
SOCK=/run/sosdeploy.sock
RESULTS=$OUT/results.txt
SCENARIO=""

# Values that must never show in a job's log.
GREETING=greet-$RANDOM-s3cret
NODE_SECRET=npm-$RANDOM-s3cret

command -v jq >/dev/null || { echo "jq is needed" >&2; exit 2; }

cleanup() {
    docker rm -f -v $M >/dev/null 2>&1
    return 0
}
trap cleanup EXIT INT TERM

say() { printf '%s\n' "$*"; }
m() { docker exec $M "$@"; }
msh() { docker exec $M sh -c "$*"; }

scenario() {
    SCENARIO=$1
    say ""
    say "---- [$STORE] scenario $1: $2"
}

record() { echo "$STORE|$SCENARIO|$1|$2" >>"$RESULTS"; }

check() {
    local name=$1; shift
    if "$@" >"$OUT/last.out" 2>&1; then
        say "  PASS  $name"
        record PASS "$name"
    else
        say "  FAIL  $name"
        sed 's/^/        | /' "$OUT/last.out" | tail -12
        record FAIL "$name"
    fi
}

# job JSON: sends a job as the panel would; prints the answer.
job() {
    local answer
    answer=$(printf '%s\n' "$1" | docker exec -i $M socat -t 3600 -T 3600 - UNIX-CONNECT:$SOCK)
    printf '%s\n' "$answer" >>"$OUT/answers.jsonl"
    printf '%s\n' "$answer"
}

state_is() { [ "$(printf '%s' "$2" | jq -r .state)" = "$1" ] || { printf '%s\n' "$2" | jq -c '{state, error, log: (.log[-25:])}'; return 1; }; }
succeeded() { state_is succeeded "$1"; }
failed() { state_is failed "$1"; }
field_is() { # answer jq-path expected
    local got
    got=$(printf '%s' "$1" | jq -r "$2")
    [ "$got" = "$3" ] || { echo "$2 is $got, wanted $3"; return 1; }
}
json_has() { printf '%s' "$1" | jq -r "$2" | grep -qF -- "$3" || { echo "$2 doesn't have $3"; return 1; }; }
# grep reads all of jq's output (no -q): stopping early would kill jq with
# SIGPIPE on a long log, and pipefail would call a match a failure.
log_has() { printf '%s' "$1" | jq -r '.log[]' | grep -F -- "$2" >/dev/null || { echo "the log never says: $2"; return 1; }; }
log_lacks() { ! printf '%s' "$1" | jq -r '.log[], (.error // {} | tostring)' | grep -F -- "$2"; }
serves() { # port text
    local i body
    for i in $(seq 20); do
        body=$(m curl -fsS --max-time 5 "http://127.0.0.1:$1/" 2>/dev/null) && printf '%s' "$body" | grep -qF -- "$2" && return 0
        sleep 1
    done
    echo "127.0.0.1:$1 answered: ${body:-nothing}"
    return 1
}
port_of() { printf '%s' "$1" | jq -r .result.port; }

health='{"path":"/","expected_status":200,"timeout_secs":5,"retries":8}'

deploy_json() { # service repo commit port env build
    jq -cn --arg s "$1" --arg r "$2" --arg c "$3" --argjson p "$4" --argjson env "$5" --argjson build "$6" --argjson h "$health" \
        '{type:"deploy",service:$s,repo:$r,commit:$c,port:$p,env:$env,build:$build,health:$h,snapshot_before:false}'
}

# ------------------------------------------------------------------ setup

mkdir -p "$OUT"
: >"$OUT/answers.jsonl"
: >"$RESULTS"

say "== building the machine image"
docker build -q -t serveros-e2e-deploy-machine $HERE >/dev/null || exit 1
ARCH=$(docker image inspect -f '{{.Architecture}}' serveros-e2e-deploy-machine)

say "== building deploy-harness for linux/$ARCH (cached in target-linux/e2e-$ARCH)"
# Built for the machine's own architecture, so it doesn't run emulated, and
# without debug info or incremental files, to keep the build small.
docker run --rm --platform linux/$ARCH \
    -v "$ROOT":/src \
    -v "$HOME/.cargo/registry":/usr/local/cargo/registry \
    -w /src -e CARGO_TARGET_DIR=/src/target-linux/e2e-$ARCH \
    -e CARGO_INCREMENTAL=0 -e CARGO_PROFILE_DEV_DEBUG=0 \
    rust:1-bookworm cargo build -q -p daemon-deploy --example deploy-harness || exit 1
HARNESS=$ROOT/target-linux/e2e-$ARCH/debug/examples/deploy-harness

say "== starting the machine ($STORE image store)"
cleanup
docker run -d --privileged --name $M --hostname machine \
    -e STORE=$STORE \
    -v /var/lib/docker -v /var/lib/containerd \
    -v "$HARNESS":/opt/deploy-harness:ro \
    serveros-e2e-deploy-machine >/dev/null || exit 1
for _ in $(seq 60); do m test -S $SOCK 2>/dev/null && break; sleep 1; done
m test -S $SOCK || { say "the harness didn't start"; docker logs $M; m cat /var/log/harness.out; exit 1; }

say "== making the fixture repositories"
docker cp $HERE/fixtures $M:/srv/fixtures >/dev/null || exit 1
m chown -R root:root /srv/fixtures || exit 1
for app in node-express static-site flask dockerfile nothing; do
    msh "cd /srv/fixtures/$app && git init -q -b main && git add -A \
        && git -c user.name=e2e -c user.email=e2e@example.com commit -qm $app && git rev-parse HEAD" \
        >"$OUT/commit-$app" || exit 1
done
repo() { echo "file:///srv/fixtures/$1"; }
commit() { cat "$OUT/commit-$1"; }

# --------------------------------------------------------------- scenarios

scenario 1 "a deploy before Docker is installed says so"
answer=$(job "$(deploy_json web-docker "$(repo dockerfile)" "$(commit dockerfile)" 8080 '{}' '{"method":"dockerfile"}')")
check "it fails" failed "$answer"
check "saying Docker isn't installed" field_is "$answer" .error.message "Docker isn't installed on this machine"
check "and how to fix it" field_is "$answer" .error.next_step "Install Docker from the machine's page in ServerOS."

scenario 2 "docker_install installs Docker from Docker's repository"
answer=$(job '{"type":"docker_install"}')
check "it succeeds" succeeded "$answer"
check "it installed Docker" field_is "$answer" .result.installed true
check "it reports the version" json_has "$answer" .result.version .
check "Compose is there" m docker compose version
check "Buildx is there" m docker buildx version
check "from Docker's own repository" m test -f /etc/apt/sources.list.d/docker.sources
answer=$(job '{"type":"docker_install"}')
check "a second time it does nothing" field_is "$answer" .result.installed false
if [ "$STORE" = classic ]; then
    check "Docker keeps images the classic way" sh -c "! docker exec $M docker info --format '{{json .DriverStatus}}' | grep -q containerd"
else
    check "Docker keeps images in containerd" sh -c "docker exec $M docker info --format '{{json .DriverStatus}}' | grep -q io.containerd.snapshotter"
fi

scenario 3 "repo_inspect reads a repository without building it"
answer=$(job "$(jq -cn --arg r "$(repo node-express)" '{type:"repo_inspect",repo:$r}')")
check "it succeeds" succeeded "$answer"
check "at the branch's commit" field_is "$answer" .result.commit "$(commit node-express)"
check "on the default branch" field_is "$answer" .result.default_branch main
check "listing the files" field_is "$answer" '.result.files | index("index.js") != null' true
check "with package.json read" json_has "$answer" '.result.contents["package.json"]' express
check "and nothing left behind" sh -c "[ -z \"\$(docker exec $M ls /var/lib/serveros/jobs)\" ]"

scenario 4 "a Dockerfile app, with a build setting and a target stage"
build=$(jq -cn --arg g "$GREETING" '{method:"dockerfile",target:"web",args:{GREETING:$g}}')
answer=$(job "$(deploy_json web-docker "$(repo dockerfile)" "$(commit dockerfile)" 8080 '{}' "$build")")
check "it deploys" succeeded "$answer"
check "built from its Dockerfile" field_is "$answer" .result.build_method dockerfile
check "it serves the page the build setting made" serves "$(port_of "$answer")" "$GREETING"
check "the setting's value never shows in the log" log_lacks "$answer" "$GREETING"
check "where the build printed it, it's redacted" log_has "$answer" "greeting is [redacted]"
answer=$(job "$(deploy_json web-docker "$(repo dockerfile)" "$(commit dockerfile)" 8080 '{"X":"1"}' "$build")")
check "deployed again, the image is reused" log_has "$answer" "already built with the same files"
nocache=$(printf '%s' "$build" | jq -c '. + {no_cache:true}')
answer=$(job "$(deploy_json web-docker "$(repo dockerfile)" "$(commit dockerfile)" 8080 '{"X":"2"}' "$nocache")")
check "with no_cache it builds from scratch" log_has "$answer" "building from scratch"
check "and still serves" serves "$(port_of "$answer")" "$GREETING"

scenario 5 "a Node app with no Dockerfile, built by Railpack"
build=$(jq -cn --arg t "$NODE_SECRET" '{method:"railpack",start_command:"node index.js",args:{NPM_SECRET:$t}}')
answer=$(job "$(deploy_json web-node "$(repo node-express)" "$(commit node-express)" 3000 '{"PORT":"3000","HOST":"0.0.0.0"}' "$build")")
check "it deploys" succeeded "$answer"
check "built by Railpack" field_is "$answer" .result.build_method railpack
check "the log says what Railpack found" log_has "$answer" "found a node app"
check "and the start command it was given" log_has "$answer" "start command: node index.js"
check "it serves on its port" serves "$(port_of "$answer")" "hello from express"
check "the build setting's value never shows in the log" log_lacks "$answer" "$NODE_SECRET"
answer=$(job "$(deploy_json web-node "$(repo node-express)" "$(commit node-express)" 3000 '{"PORT":"3000","HOST":"0.0.0.0","X":"1"}' "$build")")
check "deployed again, the Railpack image is reused" log_has "$answer" "already built with the same files"
check "and serves" serves "$(port_of "$answer")" "hello from express"

scenario 6 "a static site, built by Railpack"
answer=$(job "$(deploy_json web-static "$(repo static-site)" "$(commit static-site)" 8080 '{"PORT":"8080"}' '{"method":"railpack"}')")
check "it deploys" succeeded "$answer"
check "the log says it's a static site" log_has "$answer" "found a staticfile app"
check "it serves the page" serves "$(port_of "$answer")" "a static site, built by Railpack"

scenario 7 "a Flask app with requirements.txt, built by Railpack"
answer=$(job "$(deploy_json web-flask "$(repo flask)" "$(commit flask)" 8000 '{"PORT":"8000"}' '{"method":"railpack"}')")
check "it deploys" succeeded "$answer"
check "the log says it's a Python app" log_has "$answer" "found a python app"
check "it serves" serves "$(port_of "$answer")" "hello from flask"

scenario 8 "a prebuilt image"
image_commit=$(msh "printf nginx:alpine | sha1sum | cut -c1-40")
answer=$(job "$(deploy_json web-nginx "" "$image_commit" 80 '{}' '{"method":"image","image":"nginx:alpine"}')")
check "it deploys" succeeded "$answer"
check "from the image" field_is "$answer" .result.build_method image
check "the log has the digest it pulled" log_has "$answer" "@sha256:"
check "it serves" serves "$(port_of "$answer")" "Welcome to nginx"
check "tagged as the release's own image" m docker image inspect "serveros/web-nginx:${image_commit:0:12}"

scenario 9 "an app Railpack can't read fails with a next step"
answer=$(job "$(deploy_json web-nothing "$(repo nothing)" "$(commit nothing)" 3000 '{}' '{"method":"railpack"}')")
check "it fails" failed "$answer"
check "saying Railpack couldn't tell how to build it" field_is "$answer" .error.message "Railpack couldn't tell how to build this app"
check "and what to do" field_is "$answer" .error.next_step "Add a Dockerfile to the repository, or set a start command in the app's build settings."

scenario 10 "the apps keep serving"
for pair in "web-node:hello from express" "web-static:a static site" "web-flask:hello from flask" "web-nginx:Welcome to nginx"; do
    svc=${pair%%:*}; text=${pair#*:}
    port=$(jq -r --arg s "$svc" 'select(.result.service == $s) | .result.port' "$OUT/answers.jsonl" | tail -1)
    check "$svc" serves "$port" "$text"
done

m cat /var/log/harness.out >"$OUT/harness-$STORE.out" 2>&1
cleanup

# ----------------------------------------------------------------- results

say ""
say "======== results ($STORE image store)"
failed_any=0
for s in 1 2 3 4 5 6 7 8 9 10; do
    if grep -q "^$STORE|$s|FAIL|" "$RESULTS"; then
        printf '  scenario %-3s FAIL\n' "$s"; failed_any=1
    elif grep -q "^$STORE|$s|PASS|" "$RESULTS"; then
        printf '  scenario %-3s pass\n' "$s"
    fi
done
say ""
say "$(grep -c '|PASS|' "$RESULTS") checks passed, $(grep -c '|FAIL|' "$RESULTS") failed; details in $RESULTS"
exit $failed_any
