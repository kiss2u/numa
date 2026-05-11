#!/usr/bin/env bash
# Spin up Numa-bench (5454) + Unbound (5456), run the
# `recursive_compare --vs-unbound[-cold]` Criterion bench, tear down.
#
# Usage:
#   scripts/bench-vs-unbound.sh           # warm cache, forwarding mode
#   scripts/bench-vs-unbound.sh --cold    # unique subdomains, recursive mode
set -euo pipefail

MODE="warm"
if [[ "${1:-}" == "--cold" ]]; then
  MODE="cold"
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d -t numa-bench-vs-unbound.XXXXXX)"
NUMA_PID=""
UNBOUND_PID=""

cleanup() {
  [[ -n "$NUMA_PID" ]] && kill "$NUMA_PID" 2>/dev/null || true
  [[ -n "$UNBOUND_PID" ]] && kill "$UNBOUND_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

if [[ "$MODE" == "cold" ]]; then
  # Both servers recurse from roots — apples-to-apples cold path.
  NUMA_TOML="benches/numa-bench-recursive.toml"
  BENCH_FLAG="--vs-unbound-cold"
  cat >"$WORK/unbound.conf" <<EOF
server:
    verbosity: 0
    interface: 127.0.0.1@5456
    do-ip6: no
    do-tcp: yes
    access-control: 127.0.0.0/8 allow
    username: ""
    chroot: ""
    pidfile: "$WORK/unbound.pid"
    use-syslog: no
    logfile: "$WORK/unbound.log"
    cache-min-ttl: 60
    cache-max-ttl: 3600
    prefetch: yes
EOF
else
  # Both servers forward to Quad9 over plain UDP — canonical cached comparison.
  NUMA_TOML="benches/numa-bench.toml"
  BENCH_FLAG="--vs-unbound"
  cat >"$WORK/unbound.conf" <<EOF
server:
    verbosity: 0
    interface: 127.0.0.1@5456
    do-ip6: no
    do-tcp: yes
    access-control: 127.0.0.0/8 allow
    username: ""
    chroot: ""
    pidfile: "$WORK/unbound.pid"
    use-syslog: no
    logfile: "$WORK/unbound.log"
    cache-min-ttl: 60
    cache-max-ttl: 3600
    prefetch: yes
forward-zone:
    name: "."
    forward-addr: 9.9.9.9
EOF
fi

echo "==> mode: $MODE (numa: $NUMA_TOML)"

echo "==> building numa (release)"
cargo build --release --bin numa 2>&1 | tail -3

echo "==> starting unbound on 127.0.0.1:5456"
/opt/homebrew/sbin/unbound -c "$WORK/unbound.conf" -d >"$WORK/unbound.stderr" 2>&1 &
UNBOUND_PID=$!

echo "==> starting numa-bench on 127.0.0.1:5454"
"$ROOT/target/release/numa" "$ROOT/$NUMA_TOML" >"$WORK/numa.log" 2>&1 &
NUMA_PID=$!

echo "==> waiting for both servers"
for i in $(seq 1 30); do
  ok_u=0; ok_n=0
  dig @127.0.0.1 -p 5456 example.com +short +time=1 +tries=1 >/dev/null 2>&1 && ok_u=1
  dig @127.0.0.1 -p 5454 example.com +short +time=1 +tries=1 >/dev/null 2>&1 && ok_n=1
  if [[ $ok_u -eq 1 && $ok_n -eq 1 ]]; then
    echo "    ready (after ${i}s)"
    break
  fi
  sleep 1
  if [[ $i -eq 30 ]]; then
    echo "ERROR: servers did not become ready"
    echo "--- unbound stderr ---"; tail -20 "$WORK/unbound.stderr" || true
    echo "--- numa log ---"; tail -20 "$WORK/numa.log" || true
    exit 1
  fi
done

echo "==> running cargo bench --bench recursive_compare -- $BENCH_FLAG"
cd "$ROOT"
cargo bench --bench recursive_compare -- "$BENCH_FLAG"
