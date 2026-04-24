# DoH on the LAN

Numa ships an RFC 8484 DoH endpoint (`POST /dns-query`) on the `[proxy]` HTTPS listener. By default it binds `127.0.0.1:443` with a self-signed cert — invisible to anything off the box. Three changes make it reachable from the LAN.

## When to use this

- Your phone/laptop is on the same network as Numa and you want encrypted DNS without a cloud resolver.
- You're OK installing Numa's self-signed CA on every client (one-time, via `/ca.pem` + the mobileconfig flow).

For a publicly-trusted cert, see [dnsdist in front of Numa](dnsdist-front.md) instead.

## Minimal config

```toml
[proxy]
enabled   = true       # default
bind_addr = "0.0.0.0"  # was 127.0.0.1 — expose to LAN
tls_port  = 443        # default; DoH is served here
tld       = "numa"     # default — self-resolving, see below
```

`tld` is the DoH gate: Numa accepts the DoH request only when the `Host` header is loopback or equals (or is a subdomain of) `tld`. Clients therefore dial `https://numa/dns-query`.

With the default `tld = "numa"`, there's no DNS bootstrap to configure: Numa already resolves `numa` and `*.numa` to its own LAN IP for remote clients (that's how the `*.numa` service-proxy feature works). Any client that uses Numa as its resolver will resolve `numa` correctly on first try.

If you'd rather use a hostname that resolves via normal DNS (e.g. you want DoH-only clients that never talk plain DNS to Numa), set `tld = "dns.example.com"` and add a matching A record in whichever DNS your clients consult before reaching Numa.

## Trust the CA on each client

Numa generates a self-signed CA at startup. Fetch it once, import it wherever you'll run the DoH client:

```bash
curl -o numa-ca.pem http://<numa-ip>:5380/ca.pem
```

- **macOS** — `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain numa-ca.pem`
- **iOS** — install the mobileconfig from the API (same CA, signed profile). Flip *Settings → General → About → Certificate Trust Settings* on after install.
- **Linux** — drop into `/usr/local/share/ca-certificates/` and run `sudo update-ca-certificates`.
- **Android** — requires the user-installed CA path; browsers may still refuse it for DoH. Consider the [dnsdist front](dnsdist-front.md) route instead.

## Verify

```bash
kdig +https @numa example.com
```

Without `+https` kdig uses plain DNS. With `+https` the same answers should flow over port 443.

Raw check:

```bash
curl -H 'accept: application/dns-message' \
     --data-binary @query.bin \
     https://numa/dns-query
```

## Gotchas

- Port 443 is privileged on Linux/macOS. Run Numa via the provided service units, or grant `CAP_NET_BIND_SERVICE` (`sudo setcap 'cap_net_bind_service=+ep' /path/to/numa`).
- Non-matching `Host` header → HTTP 404 from the proxy's fallback handler. Double-check `tld`.
- ChromeOS enrollment rejects user-installed CAs for some flows — known pain point, see issue #136.
