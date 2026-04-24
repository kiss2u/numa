# ODoH upstream with bootstrap pinning

Numa can run as an Oblivious DoH (RFC 9230) client: the relay sees your IP but not the question, the target sees the question but not your IP. Neither party alone can re-identify a query. This recipe covers the minimal config and the bootstrap leak that `relay_ip` / `target_ip` close.

## When to use this

- You want split-trust encrypted DNS without a single provider seeing both who you are and what you asked.
- Numa is your system resolver (so there's no "other" DNS to ask).

## Minimal config

```toml
[upstream]
mode   = "odoh"
relay  = "https://odoh-relay.numa.rs/relay"
target = "https://odoh.cloudflare-dns.com/dns-query"
strict = true   # refuse to fall back to a non-oblivious path on relay failure
```

`strict = true` means a relay-level HTTPS failure returns SERVFAIL instead of silently downgrading. Set it to `false` and configure `[upstream].fallback` if you'd rather keep resolving (at the cost of the oblivious property).

## The bootstrap leak

When Numa is the system resolver and needs to reach the relay/target, *something* has to translate `odoh-relay.numa.rs` → IP. If Numa asks itself, you deadlock. If Numa asks a bootstrap resolver (1.1.1.1, 9.9.9.9), that resolver learns which ODoH endpoint you use in cleartext — it can't see your questions, but it sees the destination. That's the leak ODoH was supposed to close.

`relay_ip` and `target_ip` tell Numa the IPs directly, so it never asks anyone:

```toml
[upstream]
mode      = "odoh"
relay     = "https://odoh-relay.numa.rs/relay"
target    = "https://odoh.cloudflare-dns.com/dns-query"
relay_ip  = "178.104.229.30"     # pin the relay — no hostname lookup
target_ip = "104.16.249.249"     # pin the target — no hostname lookup
```

Numa still validates TLS against the hostnames in `relay` / `target`, so a hijacked IP can't masquerade — pinning skips only the DNS step.

## Finding current IPs

```bash
dig +short odoh-relay.numa.rs
dig +short odoh.cloudflare-dns.com
```

Re-pin when an operator rotates. The community-maintained list at <https://github.com/DNSCrypt/dnscrypt-resolvers/blob/master/v3/odoh-relays.md> is a useful cross-reference.

## Verify

```bash
kdig @127.0.0.1 example.com
```

Numa's `/queries` API and startup banner should label the upstream as `odoh://`. Look for `ODoH relay returned ...` errors in the logs if routing fails.

## Known gotchas

- **Same-operator refused.** Numa's eTLD+1 check blocks configs where the relay and target belong to the same operator (pointless — same party sees both sides). Override only when testing.
- **Single relay.** Current config accepts one relay and one target. Multi-entry rotation/failover is tracked in #140.
