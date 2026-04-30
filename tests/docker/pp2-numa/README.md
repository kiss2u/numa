# PROXY v2 e2e: HAProxy → numa

End-to-end harness for PR #156. HAProxy runs as an L4 front-end on two
ports — DoT (:853) and plain DNS-over-TCP (:53) — prepends a PROXY v2
header to each backend stream, and forwards bytes to numa. Numa parses
the PROXY header before the next layer (TLS for DoT, length-prefixed DNS
for plain TCP) and records the real client IP via
`/stats.proxy_protocol.*` counters.

```
host kdig +tls ──TLS──> haproxy :853 ──PROXY v2 + TLS bytes──> numa :853 ──forward──> 9.9.9.9
host dig  +tcp ──TCP──> haproxy :53  ──PROXY v2 + DNS bytes──> numa :53  ──forward──> 9.9.9.9
```

## Run the smoke

```sh
./smoke.sh
```

Builds the local numa Dockerfile, starts haproxy, queries both DoT and
plain TCP DNS through it from the host, and asserts
`/stats.proxy_protocol.accepted` increments after each.

## Manual probe

```sh
docker compose up -d --build

# DoT through haproxy
kdig +tls @127.0.0.1 -p 5853 example.com

# plain TCP DNS through haproxy
dig +tcp @127.0.0.1 -p 15353 example.com

# numa stats — proxy_protocol.accepted grows with each query
curl -s http://127.0.0.1:15380/stats | jq '.proxy_protocol'

# real client IP visibility
docker compose logs numa | grep -i pp2
```

## Tear down

```sh
docker compose down -v
```

## Why HAProxy, not dnsdist

This was originally written to test dnsdist → numa, but dnsdist 2.0's
`useProxyProtocol=true` on a TLS backend sends the PROXY header
**inside** the TLS session ("encrypted PROXY", BIND 9's
`proxy encrypted` mode). PR #156's "Out of scope" section explicitly
calls this case out — numa parses PROXY v2 before the TLS handshake.

Verified empirically with `tcpdump -X` on the bridge: the first PSH
packet from dnsdist starts with `0x16 0x03 0x01 …` (TLS ClientHello),
not the PROXY v2 signature `0x0D 0x0A 0x0D 0x0A 0x00 0x0D 0x0A 0x51 …`.

`proxyProtocolOutsideTLS` exists in dnsdist but only as an
`addLocal` / `addDOTLocal` *frontend* option (for receiving), not a
`newServer` (sending) option.

Use HAProxy `mode tcp` with `send-proxy-v2`, nginx `stream` with
`proxy_protocol on`, or any cloud L4 LB (AWS NLB, GCP TCP LB) instead.
