# Egress Control — Design Document

**Status:** Draft (pending review)
**Owner:** SatriaBagusNurhadianto
**Related:** `FEATURES.md` (Full+ profile, `egress_control` feature flag), `internal/ssrf` (existing SSRF protection)

## 1. Problem statement

7Guard is a reverse proxy sitting in front of a backend. Today it inspects *inbound* traffic. It has no control over *outbound* (egress) connections that 7Guard itself initiates — primarily the upstream dial, but also any future external fetches (webhooks, DNS lookups, health checks). A compromised rule, misconfigured upstream, or SSRF-adjacent code path could cause 7Guard to dial an unintended host, exfiltrating data or reaching internal services.

## 2. Threat model & enforcement boundary

**Scope: (a) — what 7Guard itself dials.** This includes the upstream dial and any outbound fetches initiated by 7Guard code. It does NOT include what the backend application reaches on its own; that is infrastructure-level (network policy, sidecar, eBPF) and cannot be enforced by a Go reverse proxy. Documenting this boundary avoids a false promise. The existing `ssrf_basic`/`ssrf_advanced` flags already cover part of (a); egress control composes with them rather than duplicating.

**Enforcement point:** a custom `DialContext` on the proxy's `http.Transport`, plus `CheckRedirect` on any `http.Client` used internally. All outbound dials pass through this gate.

## 3. Goals

- Allow outbound connections only to an explicit allowlist of hosts/IPs/CIDRs.
- Detect mode: allow + log + metric (default for initial rollout).
- Block mode: deny the connection; return 502/503 to the caller.
- Default-deny when the allowlist is empty in block mode.
- Compose with existing SSRF protection.

## 4. Non-goals

- Controlling the backend's own outbound traffic (out of scope; see §2).
- Full network policy / firewall replacement.
- Per-request egress quotas or rate limiting (use existing rate limiter).

## 5. Configuration

```yaml
egress:
  mode: detect          # detect | block
  allowed_hosts:        # hostnames, IPs, CIDRs, wildcard suffixes
    - api.example.com
    - "*.example.com"
    - 10.0.0.0/8
    - 2001:db8::/32
```

- `EgressMode` defaults to `detect`.
- `EgressAllowedHosts` defaults to empty.
- When `mode=block` and the list is empty → default-deny (all outbound blocked).
- Config validation at load time: reject malformed host/CIDR; no silent allow. Invalid entries cause a load error (fail-closed).

## 6. Design: resolve-validate-dial

A naive "check hostname string, then dial" is bypassable via DNS rebinding. The safe pattern:

1. **Resolve** the hostname to IP(s) using `net.Resolver`.
2. **Validate** every resolved IP against the allowlist (host, IP, CIDR, wildcard suffix). If any resolved IP is denied → deny.
3. **Dial** the validated IP directly, preserving TLS SNI and the original `Host` header.

This is implemented as a custom `DialContext` that wraps `net.Dialer`.



### Two-phase matching (hostname vs. IP allowlist)

Implementers often conflate hostname and IP allowlist entries, which breaks the
filter. The match is two-phase:

1. **Hostname phase** — entries that are hostnames (or wildcard suffixes like
   `*.example.com`) are matched against the **original request hostname** before
   resolution. If matched, the connection is allowed (subject to DNS-rebinding
   checks on the resolved IP).
2. **IP phase** — entries that are IPs or CIDRs are matched against the
   **resolved IP(s)** of the hostname.

A hostname allowlist entry never matches an IP, and a CIDR entry never matches a
hostname string. Concretely: `api.example.com` allows only that hostname;
`10.0.0.0/8` allows any hostname that resolves into that range. Both phases run;
a connection is allowed if *either* phase matches and the resolved IP passes
rebinding checks.

### Redirect handling

`http.Transport`/`http.Client` `CheckRedirect` must re-validate the target host on every redirect. Default redirect following (up to 10) is disabled unless the target passes the allowlist. Cross-host redirects are denied.

### Normalization

- Hostnames: lowercase, trim trailing dot.
- IPs: `net.ParseIP`, handle IPv4-mapped IPv6 (`::ffff:127.0.0.1` → `127.0.0.1`).
- Wildcard suffix: `*.example.com` matches `foo.example.com` and `bar.foo.example.com`, but not `example.com` itself.
- CIDR: IPv4 + IPv6.
- URL userinfo: strip/validate; `http://allowed@evil.com` is rejected (host is `evil.com`).

### Empty/missing host

Any request with an empty or missing host is denied (fail-closed).

## 7. Acceptance criteria (QA)

1. Allow/deny per host, CIDR (IPv4 + IPv6), wildcard suffix (`*.example.com`).
2. Detect vs. block modes: block denies the connection; detect allows + logs + metric.
3. Default-deny when `EgressAllowedHosts` is empty in block mode.
4. Config validation: malformed host/CIDR rejected at load time; no silent allow.
5. Observability: egress allow/deny counters in `/metrics` (reuses Phase 5 metrics package).
6. DNS rebinding protection (resolve-then-validate-then-dial).
7. Redirect bypass protection (`CheckRedirect` re-validates).
8. Case sensitivity and trailing dots handled.
9. IPv4-mapped IPv6 handled.
10. URL userinfo rejected.
11. Empty/missing host denied.

## 8. Security pitfalls & required tests

| Pitfall | Test |
|---|---|
| DNS rebinding | Mock resolver returns denied IP after hostname check → connection denied |
| Redirect bypass | Redirect to denied host → denied, no connection |
| Case sensitivity | `API.Example.COM` → normalized, matched |
| Trailing dot | `example.com.` → normalized |
| IPv4-mapped IPv6 | `::ffff:127.0.0.1` → treated as `127.0.0.1` |
| URL userinfo | `http://allowed@evil.com` → denied |
| Empty host | `http:///path` → denied |
| Default deny | empty allowlist + block mode → all denied |
| Detect mode | denied host → allowed + logged + metric incremented |

## 9. Observability

New metrics (added to `internal/metrics`):
- `egress_allowed_total` (counter)
- `egress_denied_total` (counter, by reason: allowlist, dns_rebinding, redirect, userinfo, empty_host, invalid)

Structured log record per egress decision: request_id, target_host, resolved_ip, action, reason. No secrets/PII.

## 10. Implementation plan (after design approval)

1. `internal/egress` package: `Allowlist`, `Check(host) (bool, reason)`, `DialContext` wrapper, `CheckRedirect`.
2. Config: `EgressMode`, `EgressAllowedHosts`, validation.
3. Proxy wiring: apply `DialContext` to transport; register `/metrics` already exists.
4. Tests: unit (allow/deny, normalization, CIDR, wildcard) + integration (detect/block, default-deny, rebinding, redirect, userinfo).
5. `FEATURES.md`: egress control stays Full+ (already listed).

## 11. Open questions

- Should egress control be gated behind `HasFeature("egress_control")` (Full+) or always available? Recommendation: feature-gated, default off for Lite.
- Should the allowlist support environment-variable expansion? Recommendation: no, keep config static.

## 12. Review checklist

- [ ] Threat model & boundary agreed
- [ ] Acceptance criteria agreed
- [ ] Security pitfalls covered by tests
- [ ] Config validation fail-closed
- [ ] Observability counters added
- [ ] Design approved before implementation
