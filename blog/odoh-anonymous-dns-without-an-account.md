---
title: "Anonymous DNS without an account: shipping ODoH client + relay in one Rust binary"
description: "Every existing anonymous-DNS option (Apple Private Relay, NextDNS, Cloudflare Families) requires signing up. ODoH (RFC 9230) is the protocol that splits 'who you are' from 'what you asked' across two independent operators. Numa v0.14 ships the client, the relay, and a public deployment in one MIT-licensed binary. Here's what the protocol actually does, what it doesn't fix, and what it took to deploy the second public relay in the ecosystem."
date: 2026-04-22
---

If you run Pi-hole, AdGuard Home, or any forwarding resolver, every one of your queries goes through one operator who sees both your IP address and the question. If you switch to a recursive resolver like Unbound, your IP gets exposed to every authoritative nameserver instead - `.com` learns you exist, `google.com` learns you exist, and so does every CDN edge in the chain. DoH and DoT encrypt the *transport*; they don't change *who learns what*.

Apple's iCloud Private Relay solved this for Apple users by splitting the path: an ingress proxy sees your IP but not the request, an egress proxy sees the request but not your IP. DNS gets anonymized system-wide, but only with iCloud+ ($0.99/mo), only on iOS/macOS, and only through Apple-curated egress partners. NextDNS, Cloudflare for Families, Quad9 - all the privacy-focused DNS services - require accounts, telemetry, or both. The self-hosted audience effectively had no anonymous-DNS option without an account or a platform lock-in.

<div class="hero-metrics">
<div class="metric-card">
<div class="metric-vs">Hops that see {your IP, your question}</div>
<div class="metric-value">{1, 1} → {disjoint}</div>
<div class="metric-label">relay sees IP, target sees question</div>
</div>
<div class="metric-card">
<div class="metric-vs">Crypto primitives</div>
<div class="metric-value">all audited</div>
<div class="metric-label">odoh-rs (HPKE) · rustls (TLS) — zero custom</div>
</div>
<div class="metric-card">
<div class="metric-vs">Account required</div>
<div class="metric-value">none</div>
<div class="metric-label">single binary, MIT, default config works</div>
</div>
</div>

ODoH (RFC 9230, "Oblivious DNS over HTTPS") is the IETF protocol that does this for DNS. Numa v0.14 ships a client, a relay, and a public deployment in one binary. This post is what it does, what it doesn't fix, and what it took to deploy the second public relay in the ecosystem.

---

## How it works

<style>
.odoh-diagram {
  margin: 2rem 0;
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 1.25rem 1rem 1.5rem;
}
.odoh-diagram svg {
  display: block;
  width: 100%;
  height: auto;
  max-width: 760px;
  margin: 0 auto;
  overflow: visible;
}
.odoh-diagram .od-bracket-wire {
  fill: none;
  stroke: var(--text-dim);
  stroke-width: 1;
}
.odoh-diagram .od-bracket-label {
  font-family: var(--font-mono);
  font-size: 9px;
  letter-spacing: 0.08em;
  fill: var(--text-dim);
  text-anchor: middle;
}
.odoh-diagram .od-wire,
.odoh-diagram .od-wire-return {
  fill: none;
  stroke: var(--text-secondary);
  stroke-width: 1.5;
  stroke-dasharray: 4 4;
  opacity: 0.55;
}
.odoh-diagram .od-stroke {
  fill: var(--bg-deep);
  stroke: var(--text-secondary);
  stroke-width: 1.5;
}
.odoh-diagram .od-stroke-thin {
  fill: none;
  stroke: var(--text-dim);
  stroke-width: 1;
}
.odoh-diagram .od-trav {
  font-family: var(--font-mono);
  font-size: 11px;
  text-anchor: middle;
}
.odoh-diagram .od-trav-cipher { fill: var(--amber); }
.odoh-diagram .od-trav-plain  { fill: var(--text-secondary); }
.odoh-diagram .od-label {
  font-family: var(--font-mono);
  font-size: 10px;
  letter-spacing: 0.06em;
  fill: var(--text-primary);
  text-anchor: middle;
}
.odoh-diagram .od-pulse-glow,
.odoh-diagram .od-pulse-core {
  offset-path: path('M 130 100 L 660 100 L 680 115 Q 680 200 490 170 Q 300 200 110 165 Q 100 135 100 115 L 130 115 L 130 100');
  offset-rotate: 0deg;
  animation: od-pulse-travel 7s linear infinite;
}
@keyframes od-pulse-travel {
  from { offset-distance: 0%; }
  to   { offset-distance: 100%; }
}
@media (prefers-reduced-motion: reduce) {
  .odoh-diagram .od-pulse-glow,
  .odoh-diagram .od-pulse-core {
    animation: none;
    offset-distance: 18%;
  }
}
.od-reveals {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 0.6rem;
  margin-top: 1.25rem;
}
.od-reveal {
  background: var(--bg-deep);
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 0.6rem 0.8rem;
  font-size: 0.85rem;
  color: var(--text-secondary);
  line-height: 1.45;
}
.od-reveal strong {
  display: block;
  font-family: var(--font-mono);
  font-size: 0.7rem;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  color: var(--amber);
  margin-bottom: 0.2rem;
}
.od-reveal-return { grid-column: 1 / -1; }
@media (max-width: 640px) {
  .od-reveals { grid-template-columns: 1fr; }
  .odoh-diagram .od-trav { font-size: 9px; }
}
</style>

<figure class="odoh-diagram" aria-label="ODoH protocol bidirectional topology: request travels YOU → Numa relay → Cloudflare target → authoritative; response returns along the same path, encrypted except between target and authoritative">
<svg viewBox="0 0 760 230" xmlns="http://www.w3.org/2000/svg"><defs><radialGradient id="odoh-pulse-grad" cx="50%" cy="50%" r="50%"><stop offset="0%" stop-color="#c0623a" stop-opacity="1"/><stop offset="40%" stop-color="#c0623a" stop-opacity="0.55"/><stop offset="100%" stop-color="#c0623a" stop-opacity="0"/></radialGradient></defs><path class="od-bracket-wire" d="M 252 52 L 252 44 L 528 44 L 528 52"/><text class="od-bracket-label" x="390" y="36">INDEPENDENT OPERATORS - MUST NOT COLLUDE</text><line class="od-wire" x1="130" y1="100" x2="260" y2="100"/><line class="od-wire" x1="320" y1="100" x2="460" y2="100"/><line class="od-wire" x1="520" y1="100" x2="660" y2="100"/><path class="od-wire-return" d="M 680 115 Q 680 200 490 170 Q 300 200 110 165 Q 100 135 100 115"/><g><rect class="od-stroke" x="60" y="72" width="80" height="56" rx="3"/><rect class="od-stroke-thin" x="68" y="80" width="64" height="40"/><line class="od-stroke-thin" x1="76" y1="135" x2="124" y2="135"/></g><g><rect class="od-stroke" x="250" y="68" width="80" height="64" rx="3"/><line class="od-stroke-thin" x1="258" y1="84" x2="322" y2="84"/><line class="od-stroke-thin" x1="258" y1="100" x2="322" y2="100"/><line class="od-stroke-thin" x1="258" y1="116" x2="322" y2="116"/><circle cx="316" cy="92" r="1.8" fill="#c0623a" opacity="0.7"/></g><g><ellipse class="od-stroke" cx="490" cy="100" rx="35" ry="22"/><path class="od-stroke-thin" d="M 463 100 Q 490 110 517 100"/><path class="od-stroke-thin" d="M 463 100 Q 490 90 517 100"/><line class="od-stroke-thin" x1="490" y1="78" x2="490" y2="122"/></g><g><rect class="od-stroke" x="650" y="74" width="62" height="20" rx="2"/><rect class="od-stroke" x="650" y="98" width="62" height="20" rx="2"/><rect class="od-stroke" x="650" y="122" width="62" height="20" rx="2"/><circle cx="704" cy="84" r="1.5" fill="#a39888" opacity="0.6"/><circle cx="704" cy="108" r="1.5" fill="#a39888" opacity="0.6"/><circle cx="704" cy="132" r="1.5" fill="#a39888" opacity="0.6"/></g><text class="od-trav od-trav-cipher od-trav-1" x="295" y="60">[encrypted]</text><text class="od-trav od-trav-plain od-trav-2" x="490" y="60">A example.com?</text><text class="od-trav od-trav-plain od-trav-3" x="590" y="185">93.184.216.34</text><text class="od-trav od-trav-cipher od-trav-4" x="295" y="195">[encrypted]</text><circle class="od-pulse-glow" cx="0" cy="0" r="14" fill="url(#odoh-pulse-grad)"/><circle class="od-pulse-core" cx="0" cy="0" r="3.5" fill="#c0623a"/><text class="od-label" x="100" y="218">YOU</text><text class="od-label" x="290" y="218">NUMA RELAY</text><text class="od-label" x="490" y="218">CLOUDFLARE</text><text class="od-label" x="681" y="218">AUTHORITATIVE</text></svg>
<div class="od-reveals"><div class="od-reveal od-reveal-1"><strong>You</strong>Encrypts the query under target's HPKE pubkey. Includes a symmetric key for the response.</div><div class="od-reveal od-reveal-2"><strong>Numa relay</strong>Sees your IP. Sees only ciphertext, in both directions.</div><div class="od-reveal od-reveal-3"><strong>Cloudflare target</strong>Decrypts the question. Sees no IP - just relay's.</div><div class="od-reveal od-reveal-4"><strong>Authoritative</strong>Standard DNS recursion. Cloudflare's job, not yours.</div><div class="od-reveal od-reveal-return od-reveal-5"><strong>Return</strong>Cloudflare encrypts the answer with the symmetric key you supplied and sends it back along the same path. Relay still sees only ciphertext. Same privacy property, opposite direction.</div></div>
</figure>

Encryption uses HPKE (RFC 9180) - the same primitive as TLS Encrypted ClientHello. Cloudflare publishes [`odoh-rs`](https://crates.io/crates/odoh-rs) for the seal/open operations and I used it. Numa's hand-rolling principle is *no DNS libraries*; HPKE is a different thing, and hand-rolling crypto is the kind of decision where every hour of "I want full control" buys ten of audit anxiety.

## What it took to build

ODoH client mode plugs into Numa's existing forwarding pipeline as a fourth transport (alongside UDP, DoH, DoT). The relay is a separate mode (`numa relay [PORT]`) - same binary, different entry point, only `POST /relay` and `GET /health` exposed. Two things in the relay needed more attention than expected:

**SSRF-hardened hostname validator.** The relay opens an outbound connection to a target named in the request URL. Without validation that's textbook SSRF - a malicious client could ask it to "forward" to `169.254.169.254` and exfiltrate cloud metadata. The validator is regex-strict (RFC 1035 ASCII labels, no IDN, no IP literals, no non-443 port).

**eTLD+1 same-operator check.** ODoH's guarantee depends on relay and target being run by *different* organizations. If they share an eTLD+1, one operator can join IP and question across both legs and the whole construction is theatre. Numa rejects same-operator configs by default (intentional same-operator setups still possible)

`odoh-relay.numa.rs` runs in docker-compose on a Hetzner VPS with Caddy in front for TLS. Default Numa config pairs it with `odoh.cloudflare-dns.com` - two independent operators in the path out of the box, no shared eTLD+1. The probe script `tests/probe-odoh-ecosystem.sh` checks the whole public ecosystem in one run.

## What it doesn't fix

- **The target sees the question.** ODoH moves trust, it doesn't eliminate it. If Cloudflare wants to log every ODoH query they receive, they can, and there's no cryptographic protection against that. The protection is operational: the target doesn't know who you are, so the question is unattributed.
- **Recursive mode still leaks at the target's egress.** If your target operates in recursive mode, the walk to root/TLD/authoritative is plaintext UDP/TCP. ODoH protects the client→target hop; everything past the target is the target's problem, not the protocol's.
- **Traffic analysis is possible against small relays.** A relay handling few queries leaks correlations: if your IP is the only one talking to relay A, and Cloudflare receives exactly one query right after, the timing alone re-identifies you. The defense is volume - more users on the same relay, more padding traffic, a wider anonymity set. This is why a single-user self-hosted relay is *worse* for privacy than a busy public one.
- **The pubkey distribution is centralized.** The client fetches the target's HPKE config over plain HTTPS from the target's own well-known endpoint. If you don't trust the WebPKI to deliver the right config, you don't trust ODoH. Pkarr-published target keys are an obvious next step but aren't shipped yet.
- **DNSSEC is orthogonal.** ODoH protects the path; DNSSEC protects the answer's authenticity. You still want both, and Numa's recursive mode does both - encrypted to the target, validated against the IANA root key.

## The public ecosystem

DNSCrypt's [curated list](https://github.com/DNSCrypt/dnscrypt-resolvers/blob/master/v3/odoh-relays.md) (`v3/odoh-relays.md`, last updated September 2025) carries one relay entry, with the upstream README noting *"odohrelay-crypto-sx seems to be the only ODoH relay left."* Frank Denis runs the well-known public relay at `odoh-relay.edgecompute.app` on Fastly Compute - it's the default in `dnscrypt-proxy`, the only widely-used open-source ODoH client. Numa adds the second well-known operator at `odoh-relay.numa.rs` and ships a client that can speak to either.

This isn't a product - it's infrastructure I maintain because Numa needed it and the existing ecosystem was thin. **I'd love to see other people stand up relays.** Same binary Numa users already run; flip the mode to `relay`, point Caddy at it, done in a Sunday afternoon ([docker-compose receipt](https://github.com/razvandimescu/numa/tree/main/packaging/relay)). The protocol's privacy properties scale with operator diversity.

## What's next

For anonymous DNS today: `cargo install numa`, set `mode = "odoh"` in `numa.toml`, your queries route through two independent organizations - both open source, both inspectable. Docker users: there's a [turnkey compose recipe](https://github.com/razvandimescu/numa/tree/main/packaging/client) preconfigured with ODoH mode.

---

Numa is a DNS resolver that runs on your laptop or phone. ODoH client + self-hosted relay, recursive resolution from root with DNSSEC, ad blocking, `.numa` local domains with auto-TLS, a REST API, and a live dashboard. [github.com/razvandimescu/numa](https://github.com/razvandimescu/numa).

*Discussion: [GitHub Issues](https://github.com/razvandimescu/numa/issues) · [Hacker News](https://news.ycombinator.com/from?site=numa.rs).*
