#!/usr/bin/env bash
# Smoke test for PR #156: HAProxy front-ends numa over DoT and plain TCP DNS,
# both with PROXY v2.
#
# Brings up the compose stack, runs:
#   - kdig +tls @127.0.0.1 -p 5853   (DoT through haproxy)
#   - dig  +tcp @127.0.0.1 -p 15353  (plain TCP DNS through haproxy)
# and asserts that numa's /stats.proxy_protocol.accepted counter
# increments after each query (PROXY header parsed, real client IP
# propagated).
#
# Requirements: docker (with compose v2), kdig, dig, curl, jq.

set -euo pipefail

cd "$(dirname "$0")"

GREEN="\033[32m"; RED="\033[31m"; DIM="\033[90m"; RESET="\033[0m"
pass() { printf "  ${GREEN}✓${RESET} %s\n" "$1"; }
fail() { printf "  ${RED}✗${RESET} %s\n" "$1"; exit 1; }

for tool in docker kdig dig curl jq; do
  command -v "$tool" >/dev/null || fail "missing tool: $tool"
done

cleanup() {
  if [ "${KEEP:-0}" = "1" ]; then
    printf "${DIM}KEEP=1 — leaving stack running. tear down with: docker compose -f %s down -v${RESET}\n" "$PWD/docker-compose.yml"
    return
  fi
  docker compose down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "── haproxy+numa PROXY v2 smoke test ──"

echo "  building & starting stack..."
docker compose up -d --build >/dev/null

echo -n "  waiting for numa /health "
ready=0
for _ in $(seq 1 60); do
  if curl -fsS http://127.0.0.1:15380/health >/dev/null 2>&1; then
    echo " ok"; ready=1; break
  fi
  echo -n "."
  sleep 1
done
[ "$ready" = "1" ] || fail "numa /health never came up"

baseline=$(curl -fsS http://127.0.0.1:15380/stats | jq -r '.proxy_protocol.accepted')
pass "baseline proxy_protocol.accepted = $baseline"

echo "  kdig +tls @127.0.0.1 -p 5853 example.com ..."
out=$(kdig +tls @127.0.0.1 -p 5853 example.com +short 2>/dev/null || true)
[ -n "$out" ] || fail "kdig returned no answer (haproxy→numa DoT path broken)"
pass "DoT answer: $(echo "$out" | tr '\n' ' ')"

after_dot=$(curl -fsS http://127.0.0.1:15380/stats | jq -r '.proxy_protocol.accepted')
[ "$after_dot" -gt "$baseline" ] || fail "proxy_protocol.accepted did not increment after DoT ($baseline → $after_dot)"
pass "proxy_protocol.accepted incremented after DoT: $baseline → $after_dot"

echo "  dig +tcp @127.0.0.1 -p 15353 example.com ..."
out=$(dig +tcp @127.0.0.1 -p 15353 example.com +short 2>/dev/null || true)
[ -n "$out" ] || fail "dig returned no answer (haproxy→numa plain TCP path broken)"
pass "TCP answer: $(echo "$out" | tr '\n' ' ')"

read -r after rejected < <(curl -fsS http://127.0.0.1:15380/stats \
  | jq -r '[.proxy_protocol.accepted, ([.proxy_protocol.rejected_untrusted, .proxy_protocol.rejected_signature, .proxy_protocol.timeout] | add)] | @tsv')
[ "$after" -gt "$after_dot" ] || fail "proxy_protocol.accepted did not increment after plain TCP ($after_dot → $after)"
pass "proxy_protocol.accepted incremented after plain TCP: $after_dot → $after"
[ "$rejected" = "0" ] || fail "rejected/timeout counters non-zero: $rejected"
pass "no rejections or timeouts"

echo
echo -e "${GREEN}all checks passed${RESET}"
