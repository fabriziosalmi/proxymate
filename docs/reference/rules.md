# WAF rules

Proxymate's rule engine evaluates every request against an ordered pipeline. You define rules in the UI (**Rules** tab); this page documents what each rule type does and how they interact.

## Rule types

### Block Domain

Exact-match or wildcard-subdomain against the request's `Host` header.

```
Type:  Block Domain
Value: doubleclick.net
Match: all subdomains (*.doubleclick.net)
```

Backed by a hashed `Set<String>` — O(1) lookup regardless of list size.

### Block IP

CIDR range matching against the resolved destination IP. Useful for blocking TOR exits, known malware C2 ranges, or specific cloud providers.

```
Type:  Block IP
Value: 185.220.100.0/22
```

### Block Content

Multi-pattern search across URL, headers, and (for plain HTTP) the request body. Patterns are compiled into an Aho-Corasick automaton — any one pattern match blocks, regardless of position.

```
Type:  Block Content
Patterns:
  - api_key=
  - password=
  - authorization: bearer
```

::: warning Scope
Block Content runs on the **request** body for plain HTTP, and on **headers + URL** only for HTTPS tunnels (where the body is encrypted). With MITM enabled, it runs on decrypted body too.
:::

### Allow (highest priority)

An Allow rule bypasses all downstream blocks. Use for explicit whitelists.

```
Type:  Allow
Value: *.your-employer.com
```

Allowed hosts skip blacklist + content checks entirely. Useful when a noisy tracker feed has a false positive on a domain you need to reach.

## Evaluation order

For every request:

```
1. URL length check           → 414 if >8KB
2. Allowlist                  → skip further checks, forward
3. Mock rules                 → stealth 200 OK, log as "blocked"
4. Block Domain / Block IP    → 403, log as "blocked"
5. Block Content (URL+headers) → 403
6. Blacklist feeds            → 403
7. DNS-resolved IP blacklist  → 403
8. Exfiltration scanner       → 403 or tarpit (severity-dependent)
9. C2 detection               → 403 or log (per-setting)
10. AI agent policy           → 403 if budget/model blocked
11. Beaconing detection       → 403 or log (per-setting)
12. Forward to upstream
```

## Shadow mode

Toggle per-rule with the `SHADOW` flag. A shadowed rule logs matches as `warn` but **does not** block — the request forwards normally.

Perfect for authoring new rules against real traffic: flip on, watch for false positives in logs, refine, flip off `SHADOW` to enforce.

## Mock action

A special block variant: returns a plausible 200 response (HTML, JSON, or pixel GIF depending on the expected content type) instead of 403. Trackers that retry on error don't retry on success — they silently think they worked.

Defeats scripts that expect a specific shape of response and would otherwise retry aggressively.

## Pool-aware rules

If your upstream is a [multi-member pool](/guide/features.md#routing), you can tag rules with a member selector:

```
Type:     Block Domain
Value:    ad-tracker.cloud.example.com
Upstream: member-us-east-1    # only applies when routed there
```

Useful for per-region content policies (GDPR, etc.).

## Importing rule lists

**Rules → Import** accepts three formats:

- **Hosts files** (`0.0.0.0 tracker.example.com`) — plain, widely available
- **AdBlock Plus** (`||example.com^`) — stricter filters, widely available
- **Plain domains** — one per line

Rule de-duplication is automatic; importing the same list twice is a no-op.

## Performance

- Domain / IP rules: O(1) via hashed Set
- Content patterns: O(n) per request where n = body size (Aho-Corasick, parallel pattern match)
- Blacklist lookup: O(1) Set-of-Sets, one lookup per enabled source
- Pool member selection: O(log n) via sorted index

Measured overhead at 100 K rules across all types: median <0.3 ms per request on an M2 MacBook Air.
