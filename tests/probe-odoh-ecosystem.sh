#!/usr/bin/env bash
# Probe the public ODoH ecosystem.
#
# Source of truth: DNSCrypt's curated list at
#   https://github.com/DNSCrypt/dnscrypt-resolvers/tree/master/v3
#   - v3/odoh-servers.md  (ODoH targets)
#   - v3/odoh-relays.md   (ODoH relays)
#
# As of commit 2025-09-16 ("odohrelay-crypto-sx seems to be the only ODoH
# relay left"), the full public ecosystem is 4 targets + 1 relay. Re-run this
# script against the upstream list before making any "only N public relays"
# claim publicly.
#
# Usage: ./tests/probe-odoh-ecosystem.sh

set -uo pipefail

GREEN="\033[32m"
RED="\033[31m"
YELLOW="\033[33m"
DIM="\033[90m"
RESET="\033[0m"

UP=0
DOWN=0

probe_target() {
    local name="$1"
    local host="$2"
    local url="https://${host}/.well-known/odohconfigs"
    local start=$(date +%s%N)
    local headers
    headers=$(curl -sS -o /tmp/odoh-probe-body -D - --max-time 5 -A "numa-odoh-probe/0.1" "$url" 2>&1) || {
        DOWN=$((DOWN + 1))
        printf "  ${RED}✗${RESET} %-25s ${DIM}unreachable${RESET}\n" "$name"
        return
    }
    local elapsed_ms=$((($(date +%s%N) - start) / 1000000))
    local status
    status=$(echo "$headers" | head -1 | awk '{print $2}')
    local ctype
    ctype=$(echo "$headers" | grep -i '^content-type:' | head -1 | tr -d '\r')
    local size
    size=$(stat -f%z /tmp/odoh-probe-body 2>/dev/null || stat -c%s /tmp/odoh-probe-body 2>/dev/null || echo 0)

    if [[ "$status" == "200" ]] && [[ "$size" -gt 0 ]]; then
        UP=$((UP + 1))
        printf "  ${GREEN}✓${RESET} %-25s ${DIM}%4dms  %s bytes  %s${RESET}\n" "$name" "$elapsed_ms" "$size" "$ctype"
    else
        DOWN=$((DOWN + 1))
        printf "  ${RED}✗${RESET} %-25s ${DIM}status=%s size=%s${RESET}\n" "$name" "$status" "$size"
    fi
    rm -f /tmp/odoh-probe-body
}

probe_relay() {
    # Relays don't expose /.well-known/odohconfigs — we just verify TLS reachability
    # and that the endpoint responds to a malformed POST with an HTTP error
    # (indicating the relay path exists). A real ODoH validation requires HPKE.
    local name="$1"
    local url="$2"
    local start=$(date +%s%N)
    local status
    status=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 5 -A "numa-odoh-probe/0.1" \
        -X POST -H "Content-Type: application/oblivious-dns-message" \
        --data-binary "" "$url" 2>&1) || {
        DOWN=$((DOWN + 1))
        printf "  ${RED}✗${RESET} %-25s ${DIM}unreachable${RESET}\n" "$name"
        return
    }
    local elapsed_ms=$((($(date +%s%N) - start) / 1000000))
    # Any 2xx or 4xx means the endpoint is live (TLS works, HTTP responded).
    # 5xx or 000 (curl failure) means broken.
    if [[ "$status" =~ ^[24] ]]; then
        UP=$((UP + 1))
        printf "  ${GREEN}✓${RESET} %-25s ${DIM}%4dms  status=%s (endpoint live)${RESET}\n" "$name" "$elapsed_ms" "$status"
    else
        DOWN=$((DOWN + 1))
        printf "  ${RED}✗${RESET} %-25s ${DIM}status=%s${RESET}\n" "$name" "$status"
    fi
}

echo "ODoH targets:"
probe_target "Cloudflare"   "odoh.cloudflare-dns.com"
probe_target "crypto.sx"    "odoh.crypto.sx"
probe_target "Snowstorm"    "dope.snowstorm.love"
probe_target "Tiarap"       "doh.tiarap.org"

echo
echo "ODoH relays:"
probe_relay  "Frank Denis (Fastly)" "https://odoh-relay.edgecompute.app/proxy"

echo
TOTAL=$((UP + DOWN))
if [[ "$DOWN" -eq 0 ]]; then
    printf "${GREEN}All %d endpoints up${RESET}\n" "$TOTAL"
    exit 0
else
    printf "${YELLOW}%d/%d up, %d down${RESET}\n" "$UP" "$TOTAL" "$DOWN"
    exit 1
fi
