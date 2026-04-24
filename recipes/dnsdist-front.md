# dnsdist in front of Numa

For public DoH with a real (ACME-signed) cert, terminate TLS outside Numa and forward plain DNS (or loopback-only DoH) to the resolver. Cert renewal, rate-limiting, and load-balancing live in the front-end; Numa stays focused on resolution.

## When to use this

- Public hostname (`dns.example.com`) with a Let's Encrypt or internal PKI cert.
- You want a dedicated front-end for DoH/DoT/DoQ while Numa stays loopback-bound.
- You plan to run multiple Numa instances behind one endpoint.

## Architecture

```
 public 443/DoH  ┐
 public 853/DoT  ├─► dnsdist  ─►  127.0.0.1:53 (Numa UDP/TCP)
 public 443/DoQ  ┘
```

## dnsdist config

```lua
-- /etc/dnsdist/dnsdist.conf

newServer({address="127.0.0.1:53", name="numa", checkType="A", checkName="numa.rs."})

addDOHLocal(
  "0.0.0.0:443",
  "/etc/letsencrypt/live/dns.example.com/fullchain.pem",
  "/etc/letsencrypt/live/dns.example.com/privkey.pem",
  "/dns-query",
  {doTCP=true, reusePort=true}
)

addTLSLocal(
  "0.0.0.0:853",
  "/etc/letsencrypt/live/dns.example.com/fullchain.pem",
  "/etc/letsencrypt/live/dns.example.com/privkey.pem"
)

addAction(AllRule(), PoolAction("", false))
```

## Numa config

```toml
[proxy]
enabled   = true         # keep if you still use *.numa service routing
bind_addr = "127.0.0.1"  # stays default
```

No changes to `[server]` — Numa keeps serving plain DNS on UDP/TCP 53, which dnsdist forwards.

## Caveat: client IPs

Without PROXY protocol support in Numa, the query log shows the front-end's IP on every query, not the real client. dnsdist can emit PROXY v2 (`useProxyProtocol=true` on `newServer`), but Numa doesn't yet parse it — tracked in the wish-list under #143. Until then, accept the blind spot or correlate against dnsdist's own logs.

## Verify

```bash
kdig +https @dns.example.com example.com
kdig +tls  @dns.example.com example.com
```

Both should return clean answers. Numa's `/queries` API should show the request landing, sourced from the front-end IP.
