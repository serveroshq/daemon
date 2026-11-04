#!/usr/bin/env bash
# End-to-end test for project networks (the `network` job), on real
# WireGuard, real firewalls and real Docker, in containers standing in for
# machines.
#
#   make e2e-networks                      every firewall backend
#   tests/e2e/networks/run.sh ufw none     just these
#
# Each "machine" is a privileged Debian container running its own dockerd,
# on a Docker network "wan" standing in for the internet; their wan
# addresses are the WireGuard endpoints. On each one runs the
# network-harness example (crates/daemon-network/examples): the same
# Networks code serverosd uses, through the same job runner, restoring
# stored networks when it starts. Jobs are sent as the panel sends them.
#
# Needs: docker with a kernel that has WireGuard (Docker Desktop's does),
# jq, and network access for apt (wireguard-tools is installed by the job).
# Everything it creates is removed when it exits.
set -uo pipefail

cd "$(dirname "$0")/../../.."
ROOT=$PWD
HERE=tests/e2e/networks
OUT=$ROOT/target-linux/e2e-networks
BACKENDS=("$@")
[ ${#BACKENDS[@]} -eq 0 ] && BACKENDS=(ufw nftables iptables none)

PREFIX=e2e-net
WAN=$PREFIX-wan
WAN_SUBNET=172.31.250.0/24
WAN_A=172.31.250.11
WAN_B=172.31.250.12
WAN_C=172.31.250.13
WAN_X=172.31.250.20
NET1=t3stnet001
NET2=t3stnet002
IF1=sos$NET1
IF2=sos$NET2
PG_IMAGE=postgres:16-alpine
REDIS_IMAGE=redis:7-alpine
PGPASS=e2e-secret
SOCK=/run/sosnet.sock
STATE=/var/lib/serveros

RESULTS=$OUT/results.txt
BACKEND=""
SCENARIO=""

command -v jq >/dev/null || { echo "jq is needed" >&2; exit 2; }

# ---------------------------------------------------------------- plumbing

cleanup() {
    docker rm -f -v $PREFIX-a $PREFIX-b $PREFIX-c $PREFIX-x >/dev/null 2>&1
    docker network rm $WAN >/dev/null 2>&1
    return 0
}
trap cleanup EXIT INT TERM

say() { printf '%s\n' "$*"; }
m() { local who=$1; shift; docker exec $PREFIX-$who "$@"; }
msh() { local who=$1; shift; docker exec $PREFIX-$who sh -c "$*"; }

scenario() {
    SCENARIO=$1
    say ""
    say "---- [$BACKEND] scenario $1: $2"
}

record() { echo "$BACKEND|$SCENARIO|$1|$2" >>"$RESULTS"; }

# check NAME CMD...: passes when CMD succeeds.
check() {
    local name=$1; shift
    if "$@" >"$OUT/last.out" 2>&1; then
        say "  PASS  $name"
        record PASS "$name"
    else
        say "  FAIL  $name"
        sed 's/^/        | /' "$OUT/last.out" | tail -8
        record FAIL "$name"
    fi
}

# refute NAME CMD...: passes when CMD fails.
refute() {
    local name=$1; shift
    if "$@" >"$OUT/last.out" 2>&1; then
        say "  FAIL  $name (it worked, and shouldn't have)"
        sed 's/^/        | /' "$OUT/last.out" | tail -8
        record FAIL "$name"
    else
        say "  PASS  $name"
        record PASS "$name"
    fi
}

evidence() {
    local file=$OUT/$BACKEND/$1; shift
    "$@" >"$file" 2>&1
    sed 's/^/        > /' "$file" | head -"${LINES_SHOWN:-14}"
}

# job MACHINE JSON: sends a job as the panel would; prints the answer.
job() {
    local who=$1 json=$2 answer
    answer=$(printf '%s\n' "$json" | docker exec -i $PREFIX-$who socat -t 900 - UNIX-CONNECT:$SOCK)
    printf '%s\n' "$answer" >>"$OUT/$BACKEND/answers.jsonl"
    printf '%s\n' "$answer"
}

succeeded() { [ "$(printf '%s' "$1" | jq -r .state)" = succeeded ] || { printf '%s\n' "$1"; return 1; }; }
all_succeeded() { local a; for a in "$@"; do succeeded "$a" || return 1; done; }

up_json() { # network address port peers expose
    jq -cn --arg n "$1" --arg a "$2" --argjson p "$3" --argjson peers "$4" --argjson expose "$5" \
        '{type:"network",network:$n,action:"up",address:$a,listen_port:$p,peers:$peers,expose:$expose}'
}

down_json() { jq -cn --arg n "$1" '{type:"network",network:$n,action:"down"}'; }

peer() { # key address endpoint
    jq -cn --arg k "$1" --arg a "$2" --arg e "$3" '{public_key:$k,address:$a,endpoint:$e}'
}

peers() { jq -cs . ; }

EXP_A='[]'
EXP_B='[{"port":5432,"target":"127.0.0.1:5432"}]'
EXP_C='[{"port":6379,"target":"127.0.0.1:6379"}]'

# Network 1, as the panel does it: up with no peers to learn each key,
# then up again on every member with all the others as peers.
net1_up() { # members-with-peers: "a b c"
    local members=$1 who peers_json exp addr answer
    for who in $members; do
        peers_json=$(for other in $members; do
            [ "$other" = "$who" ] && continue
            peer "$(key_of $other)" "$(addr_of $other)/32" "$(wan_of $other):51820"
        done | peers)
        [ -z "$peers_json" ] && peers_json='[]'
        answer=$(job $who "$(up_json $NET1 "$(addr_of $who)/24" 51820 "$peers_json" "$(exp_of $who)")")
        succeeded "$answer" || { say "  up on $who failed: $answer"; return 1; }
        note_key $who "$(printf '%s' "$answer" | jq -r .result.public_key)"
    done
}

addr_of() { case $1 in a) echo 10.64.7.2;; b) echo 10.64.7.3;; c) echo 10.64.7.4;; esac; }
wan_of() { case $1 in a) echo $WAN_A;; b) echo $WAN_B;; c) echo $WAN_C;; esac; }
exp_of() { case $1 in a) echo "$EXP_A";; b) echo "$EXP_B";; c) echo "$EXP_C";; esac; }
key_of() { cat "$OUT/$BACKEND/key-$1" 2>/dev/null; }
note_key() {
    local who=$1 key=$2
    echo "$key" >>"$OUT/$BACKEND/keys-seen-$who"
    echo "$key" >"$OUT/$BACKEND/key-$who"
}

psql_from_host() { # machine host -> prints result of select 1
    m "$1" timeout 15 env PGPASSWORD=$PGPASS PGCONNECT_TIMEOUT=5 psql -h "$2" -U postgres -tAc 'select 1'
}
psql_is_one_host() { [ "$(psql_from_host "$@")" = 1 ]; }
psql_from_container() { # machine host [docker network]
    m "$1" timeout 30 docker run --rm ${3:+--network $3} -e PGPASSWORD=$PGPASS -e PGCONNECT_TIMEOUT=5 $PG_IMAGE \
        psql -h "$2" -U postgres -tAc 'select 1'
}
psql_is_one_container() { [ "$(psql_from_container "$@")" = 1 ]; }
# Redis answers a raw PING with +PONG.
redis_pong_host() { [ "$(msh "$1" "printf 'PING\r\n' | nc -w3 $2 6379 | tr -d '\r'")" = +PONG ]; }
redis_pong_container() {
    [ "$(m "$1" timeout 30 docker run --rm $REDIS_IMAGE timeout 10 redis-cli -h "$2" ping | tr -d '\r')" = PONG ]
}
tcp_open() { m "$1" nc -z -w3 "$2" "$3"; }

has_link() { m "$1" ip link show dev "$2"; }

fw_list() { # machine: the firewall as the backend sees it
    case $BACKEND in
        ufw) m "$1" ufw show added ;;
        nftables) m "$1" nft list ruleset ;;
        iptables) m "$1" iptables -S ;;
        none) m "$1" iptables -S INPUT ;;
    esac
}
fw_count() { # machine pattern: lines of the firewall mentioning pattern
    fw_list "$1" 2>/dev/null | grep -cE "$2"
}
fw_none_of() { # prints what matched, if anything
    ! fw_list "$1" 2>/dev/null | grep -E "$2"
}

handshakes_all() { # machine: every peer has handshaken
    local lines
    lines=$(m "$1" wg show "$2" latest-handshakes) || return 1
    [ -n "$lines" ] || return 1
    printf '%s\n' "$lines" | awk '$2 == 0 { bad=1 } END { exit bad }'
}
wait_handshakes() {
    local i
    for i in $(seq 20); do
        handshakes_all "$1" "$2" && return 0
        sleep 1
    done
    m "$1" wg show "$2"
    return 1
}

start_harness() {
    msh "$1" "nohup /opt/network-harness serve --state $STATE --firewall $BACKEND --socket $SOCK >>/var/log/harness.out 2>&1 &"
    local i
    for i in $(seq 30); do
        m "$1" test -S $SOCK && return 0
        sleep 0.5
    done
    say "harness on $1 didn't start"; m "$1" cat /var/log/harness.out
    return 1
}
stop_harness() { m "$1" pkill -f network-harness; sleep 1; m "$1" rm -f $SOCK; }

# A default-deny inbound firewall, the way an operator would have it.
default_deny() {
    local who=$1
    case $BACKEND in
        ufw)
            m $who ufw default deny incoming >/dev/null
            m $who ufw --force enable >/dev/null
            ;;
        nftables)
            msh $who "nft -f - <<'NFT'
table inet filter {
  chain input {
    type filter hook input priority filter; policy drop;
    ct state established,related accept
    iif lo accept
    ip protocol icmp accept
  }
}
NFT"
            ;;
        iptables)
            msh $who "iptables -I INPUT 1 -i lo -j ACCEPT && iptables -I INPUT 2 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT && iptables -P INPUT DROP"
            ;;
        none) ;;
    esac
}

# ------------------------------------------------------------------ setup

say "== building the machine image"
docker build -q -t serveros-e2e-machine $HERE >/dev/null || exit 1
ARCH=$(docker image inspect -f '{{.Architecture}}' serveros-e2e-machine)

say "== building network-harness for linux/$ARCH (cached in target-linux/e2e-$ARCH)"
# Built for the machines' own architecture, so it doesn't run emulated.
docker run --rm --platform linux/$ARCH \
    -v "$ROOT":/src \
    -v "$HOME/.cargo/registry":/usr/local/cargo/registry \
    -w /src -e CARGO_TARGET_DIR=/src/target-linux/e2e-$ARCH \
    rust:1-bookworm cargo build -q -p daemon-network --example network-harness || exit 1
HARNESS=$ROOT/target-linux/e2e-$ARCH/debug/examples/network-harness

say "== checking the kernel has WireGuard"
docker run --rm --privileged --entrypoint sh serveros-e2e-machine -c 'ip link add wgprobe type wireguard' || {
    echo "this Docker host's kernel has no WireGuard; can't run the test" >&2
    exit 3
}

say "== saving the test images"
mkdir -p "$OUT/images"
for image in $PG_IMAGE $REDIS_IMAGE; do
    file=$OUT/images/$(echo $image | tr ':/' '__').tar
    [ -f "$file" ] || { docker pull -q $image >/dev/null && docker save -o "$file" $image; } || exit 1
done
: >"$RESULTS"

start_machines() {
    cleanup
    docker network create --subnet $WAN_SUBNET $WAN >/dev/null || return 1
    local who ip
    for who in a b c x; do
        case $who in a) ip=$WAN_A;; b) ip=$WAN_B;; c) ip=$WAN_C;; x) ip=$WAN_X;; esac
        docker run -d --privileged --name $PREFIX-$who --hostname machine-$who \
            --network $WAN --ip $ip \
            -v /var/lib/docker \
            -v "$HARNESS":/opt/network-harness:ro \
            -v "$OUT/images":/images:ro \
            serveros-e2e-machine >/dev/null || return 1
    done
    for who in a b c x; do
        local i
        for i in $(seq 90); do m $who test -f /run/machine-ready 2>/dev/null && break; sleep 1; done
        m $who test -f /run/machine-ready || { say "machine $who didn't come up"; docker logs $PREFIX-$who; return 1; }
    done
    for who in a b c; do
        for f in "$OUT"/images/*.tar; do m $who docker load -q -i /images/$(basename "$f") >/dev/null; done
    done
    m b docker run -d --name pg -p 127.0.0.1:5432:5432 -e POSTGRES_PASSWORD=$PGPASS $PG_IMAGE >/dev/null
    m c docker run -d --name redis -p 127.0.0.1:6379:6379 $REDIS_IMAGE >/dev/null
    msh b "nohup socat TCP-LISTEN:9999,bind=127.0.0.1,fork,reuseaddr SYSTEM:'echo not-exposed' >/dev/null 2>&1 &"
    m b docker network create appnet >/dev/null
    for i in $(seq 60); do
        m b docker exec pg pg_isready -q -h 127.0.0.1 && break
        sleep 1
    done
    for who in a b c; do default_deny $who; start_harness $who || return 1; done
}

# --------------------------------------------------------------- scenarios

run_backend() {
    BACKEND=$1
    mkdir -p "$OUT/$BACKEND"
    rm -f "$OUT/$BACKEND"/*
    say ""
    say "======== firewall backend: $BACKEND"
    start_machines || { SCENARIO=setup; record FAIL "machines started"; return; }

    scenario 0 "phase 1 and 2 of bringing $NET1 up on a, b, c"
    rm -f "$OUT/$BACKEND"/key-*
    local answer who
    for who in a b c; do
        answer=$(job $who "$(up_json $NET1 "$(addr_of $who)/24" 51820 '[]' "$(exp_of $who)")")
        check "phase 1 up on $who (installs wireguard-tools)" succeeded "$answer"
        note_key $who "$(printf '%s' "$answer" | jq -r .result.public_key)"
    done
    say "        > $(printf '%s' "$answer" | jq -c .result)"
    check "phase 2 up on a, b, c with every other member as a peer" net1_up "a b c"
    check "interface name is sos{network}" has_link a $IF1

    scenario 1 "handshake and ping"
    check "a pings b (10.64.7.3)" m a ping -c2 -W2 10.64.7.3
    check "a pings c (10.64.7.4)" m a ping -c2 -W2 10.64.7.4
    m b ping -c1 -W2 10.64.7.4 >/dev/null 2>&1
    for who in a b c; do check "wg show on $who: a recent handshake with every peer" wait_handshakes $who $IF1; done
    LINES_SHOWN=20 evidence wg-show-a.txt m a wg show $IF1

    scenario 2 "host to service across machines"
    check "a host: psql select 1 on b's 10.64.7.3:5432 (postgres on b's 127.0.0.1)" psql_is_one_host a 10.64.7.3
    check "a host: redis PING on c's 10.64.7.4:6379" redis_pong_host a 10.64.7.4
    evidence psql-host.txt m a env PGPASSWORD=$PGPASS psql -h 10.64.7.3 -U postgres -c 'select 1 as across_the_network, inet_client_addr()'

    scenario 3 "app container across machines (docker masquerade path)"
    check "a container (default bridge): psql select 1 on 10.64.7.3" psql_is_one_container a 10.64.7.3
    check "a container (default bridge): redis-cli ping on 10.64.7.4" redis_pong_container a 10.64.7.4

    scenario 4 "same-machine containers to their own machine's network address"
    check "b container on the default bridge -> 10.64.7.3:5432" psql_is_one_container b 10.64.7.3
    check "b container on a user-defined bridge (br-*) -> 10.64.7.3:5432" psql_is_one_container b 10.64.7.3 appnet
    check "c container on the default bridge -> 10.64.7.4:6379" redis_pong_container c 10.64.7.4
    LINES_SHOWN=40 evidence firewall-b-up.txt fw_list b

    scenario 6 "isolation"
    m x ip route add 10.64.7.0/24 via $WAN_B >/dev/null 2>&1
    refute "outsider on the wan (routing 10.64.7.0/24 to b) can't psql 10.64.7.3:5432" psql_is_one_host x 10.64.7.3
    if [ $BACKEND != none ]; then
        refute "outsider can't even open a TCP connection to 10.64.7.3:5432" tcp_open x 10.64.7.3 5432
    fi
    refute "outsider can't reach b's wan address on 5432" tcp_open x $WAN_B 5432
    refute "a can't reach b's non-exposed 127.0.0.1:9999 over the network" tcp_open a 10.64.7.3 9999
    check "(b itself does have something on 127.0.0.1:9999)" tcp_open b 127.0.0.1 9999

    scenario 7 "idempotency and changes"
    local pattern="$IF1|10\.64\.7\.|51820|$NET1"
    local before_a before_b before_c
    before_a=$(fw_count a "$pattern"); before_b=$(fw_count b "$pattern"); before_c=$(fw_count c "$pattern")
    for _ in 1 2 3; do net1_up "a b c" >/dev/null; done
    check "same up 3 more times: a's firewall lines unchanged ($before_a)" [ "$(fw_count a "$pattern")" = "$before_a" ]
    check "same up 3 more times: b's firewall lines unchanged ($before_b)" [ "$(fw_count b "$pattern")" = "$before_b" ]
    check "same up 3 more times: c's firewall lines unchanged ($before_c)" [ "$(fw_count c "$pattern")" = "$before_c" ]
    check "still exactly 2 peers on a" [ "$(m a wg show $IF1 peers | wc -l | tr -d ' ')" = 2 ]
    say "        > firewall lines for the network: a=$before_a b=$before_b c=$before_c, the same after 3 more ups"

    EXP_C='[]'
    answer=$(job a "$(up_json $NET1 10.64.7.2/24 51820 "[$(peer "$(key_of b)" 10.64.7.3/32 $WAN_B:51820)]" '[]')")
    check "a: c dropped from the peers" succeeded "$answer"
    answer=$(job b "$(up_json $NET1 10.64.7.3/24 51820 "[$(peer "$(key_of a)" 10.64.7.2/32 $WAN_A:51820)]" "$EXP_B")")
    check "b: c dropped from the peers" succeeded "$answer"
    answer=$(job c "$(up_json $NET1 10.64.7.4/24 51820 "$( (peer "$(key_of a)" 10.64.7.2/32 $WAN_A:51820; peer "$(key_of b)" 10.64.7.3/32 $WAN_B:51820) | peers)" '[]')")
    check "c: its expose dropped" succeeded "$answer"
    refute "a can't reach c's 10.64.7.4:6379 any more" tcp_open a 10.64.7.4 6379
    refute "a's wg no longer has c" sh -c "docker exec $PREFIX-a wg show $IF1 peers | grep -qx '$(key_of c)'"
    check "a <-> b still works" psql_is_one_host a 10.64.7.3
    refute "c no longer forwards 6379" tcp_open c 10.64.7.4 6379
    if [ $BACKEND != none ]; then
        # Docker's own rules for the published port mention 6379 too; ours
        # are the ones naming the network address.
        check "c's 6379 firewall rules are gone" fw_none_of c "10\.64\.7\.4.*6379"
    fi
    EXP_C='[{"port":6379,"target":"127.0.0.1:6379"}]'
    check "c added back everywhere" net1_up "a b c"
    check "a reaches c's 6379 again" redis_pong_host a 10.64.7.4
    check "a container reaches c's 6379 again" redis_pong_container a 10.64.7.4

    scenario 8 "key stability and secrecy"
    for who in a b c; do
        check "$who: the same public key from every up ($(wc -l <"$OUT/$BACKEND/keys-seen-$who" | tr -d ' ') ups)" \
            [ "$(sort -u "$OUT/$BACKEND/keys-seen-$who" | wc -l | tr -d ' ')" = 1 ]
    done
    check "b: key file is 0600" [ "$(m b stat -c %a $STATE/networks/$NET1.key)" = 600 ]
    check "b: key folder is 0700" [ "$(m b stat -c %a $STATE/networks)" = 700 ]
    check "b: the key's public half is what up returned" \
        [ "$(msh b "wg pubkey < $STATE/networks/$NET1.key")" = "$(key_of b)" ]
    check "b: no wg config with the key left on disk" [ "$(m b sh -c "ls $STATE/networks/*.conf 2>/dev/null | wc -l" | tr -d ' ')" = 0 ]
    for who in a b c; do
        local private
        private=$(m $who cat $STATE/networks/$NET1.key)
        refute "$who: private key not in any job answer" grep -qF "$private" "$OUT/$BACKEND/answers.jsonl"
        refute "$who: private key not in state.db, the job log or the harness output" \
            m $who grep -rqaF "$private" $STATE/state.db $STATE/harness.log /var/log/harness.out
    done

    scenario 12 "two projects on the same machines"
    local a2 b2
    a2=$(job a "$(up_json $NET2 10.64.8.2/24 51821 '[]' '[]')")
    b2=$(job b "$(up_json $NET2 10.64.8.3/24 51821 '[]' "$EXP_B")")
    check "phase 1 for $NET2 on a and b" all_succeeded "$a2" "$b2"
    a2=$(job a "$(up_json $NET2 10.64.8.2/24 51821 "[$(peer "$(printf '%s' "$b2" | jq -r .result.public_key)" 10.64.8.3/32 $WAN_B:51821)]" '[]')")
    b2=$(job b "$(up_json $NET2 10.64.8.3/24 51821 "[$(peer "$(printf '%s' "$a2" | jq -r .result.public_key)" 10.64.8.2/32 $WAN_A:51821)]" "$EXP_B")")
    check "phase 2 for $NET2 on a and b" succeeded "$b2"
    check "$NET2 has its own key" [ "$(printf '%s' "$b2" | jq -r .result.public_key)" != "$(key_of b)" ]
    check "a -> b over $NET2 (10.64.8.3:5432)" psql_is_one_host a 10.64.8.3
    check "a -> b over $NET1 at the same time (10.64.7.3:5432)" psql_is_one_host a 10.64.7.3
    check "a container -> b over $NET2" psql_is_one_container a 10.64.8.3
    check "down $NET2 on a" succeeded "$(job a "$(down_json $NET2)")"
    check "down $NET2 on b" succeeded "$(job b "$(down_json $NET2)")"
    refute "$IF2 is gone from b" has_link b $IF2
    check "$NET1 still works after $NET2 went" psql_is_one_container a 10.64.7.3
    check "$NET1 still has its 2 peers on b" [ "$(m b wg show $IF1 peers | wc -l | tr -d ' ')" = 2 ]
    if [ $BACKEND != none ]; then
        check "$NET2's rules are gone from b" fw_none_of b "$IF2|51821|10\.64\.8\.|$NET2"
    fi

    scenario 13 "soak: 200 sequential and 50 parallel connections from a container on a"
    local soak
    soak=$(m a timeout 600 docker run --rm -e PGPASSWORD=$PGPASS -e PGCONNECT_TIMEOUT=10 $PG_IMAGE sh -c '
        ok=0; bad=0
        for i in $(seq 200); do
            if [ "$(psql -h 10.64.7.3 -U postgres -tAc "select 1" 2>/dev/null)" = 1 ]; then ok=$((ok+1)); else bad=$((bad+1)); fi
        done
        echo "sequential ok=$ok bad=$bad"
        for i in $(seq 50); do
            ( [ "$(psql -h 10.64.7.3 -U postgres -tAc "select 1 from pg_sleep(0.5)" 2>/dev/null)" = 1 ] && echo P-ok || echo P-bad ) &
        done | sort | uniq -c | tr "\n" " "; echo')
    say "        > $soak"
    echo "$soak" >"$OUT/$BACKEND/soak.txt"
    check "200 sequential: 0 failures" sh -c "echo '$soak' | grep -q 'sequential ok=200 bad=0'"
    check "50 parallel: all 50 ok" sh -c "echo '$soak' | grep -q '50 P-ok' && ! echo '$soak' | grep -q P-bad"

    scenario 9 "reboot of b: restore on start"
    stop_harness b
    m b ip link del dev $IF1
    case $BACKEND in
        nftables)
            # Not persisted: our table goes; the operator's comes back from
            # its config, without anything we added to it.
            m b nft delete table inet serveros
            m b nft delete table inet filter
            default_deny b ;;
        iptables)
            # Not persisted: our chain goes; the operator's policy stays.
            m b iptables -D INPUT -j SOS-$NET1
            m b iptables -F SOS-$NET1
            m b iptables -X SOS-$NET1 ;;
        *) ;; # ufw keeps its rules over a reboot
    esac
    refute "interface gone after the reboot" has_link b $IF1
    refute "a can't reach b while b is down" psql_is_one_host a 10.64.7.3
    start_harness b
    sleep 1
    m b grep restore /var/log/harness.out | tail -1 | cut -c1-160 | sed 's/^/        > /'
    check "interface is back" has_link b $IF1
    check "both peers are back" [ "$(m b wg show $IF1 peers | wc -l | tr -d ' ')" = 2 ]
    check "the same key is back" [ "$(m b wg show $IF1 public-key)" = "$(key_of b)" ]
    if [ $BACKEND != none ]; then
        check "firewall rules are back" [ "$(fw_count b "$IF1|51820")" -gt 0 ]
    fi
    check "scenario 2 again: a host psql to 10.64.7.3" psql_is_one_host a 10.64.7.3
    check "scenario 3 again: a container psql to 10.64.7.3" psql_is_one_container a 10.64.7.3
    check "scenario 4 again: b container to its own 10.64.7.3" psql_is_one_container b 10.64.7.3 appnet

    scenario 11 "bad input from a buggy panel"
    local good_peer bad
    good_peer=$(peer "$(key_of a)" 10.64.9.2/32 $WAN_A:51830)
    for bad in \
        "peer with a bad key|$(up_json badnet0001 10.64.9.3/24 51830 "[$(peer not-a-key 10.64.9.2/32 $WAN_A:51830)]" '[]')" \
        "address outside the private ranges|$(up_json badnet0001 8.8.8.8/24 51830 "[$good_peer]" '[]')" \
        "expose target a public IP|$(up_json badnet0001 10.64.9.3/24 51830 "[$good_peer]" '[{"port":53,"target":"1.1.1.1:53"}]')" \
        "network id with uppercase|$(up_json BADNET0001 10.64.9.3/24 51830 '[]' '[]')" \
        "network id too long|$(up_json badnet00012345 10.64.9.3/24 51830 '[]' '[]')" \
        "no listen port|$(jq -cn '{type:"network",network:"badnet0001",action:"up",address:"10.64.9.3/24"}')"; do
        local name=${bad%%|*} json=${bad#*|}
        answer=$(job b "$json")
        check "$name: refused" [ "$(printf '%s' "$answer" | jq -r .state)" = failed ]
        say "        > $(printf '%s' "$answer" | jq -c '.error | {phase, message}')"
    done
    refute "no interface left behind" sh -c "docker exec $PREFIX-b ip -o link | grep -qiE 'sosbadnet'"
    check "no firewall rules left behind" fw_none_of b "badnet|51830|10\.64\.9\."
    refute "no key file left behind" m b sh -c "ls $STATE/networks | grep -qi badnet"
    refute "nothing stored" sh -c "docker exec $PREFIX-b sqlite3 $STATE/state.db \"select value from kv where key='networks'\" | grep -qi badnet"

    scenario 10 "down"
    LINES_SHOWN=40 evidence firewall-b-before-down.txt fw_list b
    check "down on b" succeeded "$(job b "$(down_json $NET1)")"
    LINES_SHOWN=40 evidence firewall-b-after-down.txt fw_list b
    refute "b's interface is gone" has_link b $IF1
    if [ $BACKEND != none ]; then
        check "b's firewall rules are gone" fw_none_of b "$IF1|51820|10\.64\.7\.|$NET1|net_|SOS-"
    fi
    refute "b's forwarder is gone" tcp_open b 10.64.7.3 5432
    refute "b's key file is gone" m b test -e $STATE/networks/$NET1.key
    refute "b's stored spec is gone" sh -c "docker exec $PREFIX-b sqlite3 $STATE/state.db \"select value from kv where key='networks'\" | grep -q $NET1"
    refute "a can no longer reach b" psql_is_one_host a 10.64.7.3
    check "a still reaches c" redis_pong_host a 10.64.7.4
    check "down again on b (now unknown) succeeds" succeeded "$(job b "$(down_json $NET1)")"
    check "down on an id never created succeeds" succeeded "$(job b "$(down_json neverseen01)")"

    m b cat /var/log/harness.out >"$OUT/$BACKEND/harness-b.out" 2>&1
    cleanup
}

for backend in "${BACKENDS[@]}"; do run_backend "$backend"; done

# ----------------------------------------------------------------- matrix

say ""
say "======== results (scenario x firewall backend; PASS = every check passed)"
printf '%-10s' scenario
for b in "${BACKENDS[@]}"; do printf '%-10s' "$b"; done
printf '\n'
failed=0
for s in setup 0 1 2 3 4 6 7 8 9 10 11 12 13; do
    grep -q "|$s|" "$RESULTS" || continue
    printf '%-10s' "$s"
    for b in "${BACKENDS[@]}"; do
        if grep -q "^$b|$s|FAIL|" "$RESULTS"; then
            printf '%-10s' FAIL; failed=1
        elif grep -q "^$b|$s|PASS|" "$RESULTS"; then
            printf '%-10s' pass
        else
            printf '%-10s' -
        fi
    done
    printf '\n'
done
say ""
say "$(grep -c '|PASS|' "$RESULTS") checks passed, $(grep -c '|FAIL|' "$RESULTS") failed; details in $RESULTS"
exit $failed
