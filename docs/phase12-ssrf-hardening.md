# SSRF Hardening — Design Document (Phase 12)

**Status:** Draft (pending review)
**Owner:** SatriaBagusNurhadianto
**Related:** `FEATURES.md` (`ssrf_basic` feature flag, Full+ profile), `internal/egress` (egress control), `docs/egress-control.md`

## 1. Problem statement

7Guard is a reverse proxy. Today it inspects inbound traffic and controls outbound dials (egress), but it has no dedicated protection against **Server-Side Request Forgery (SSRF)**: an attacker who can influence the proxy's upstream target (or any internal fetch) can coerce 7Guard into dialing internal services, cloud metadata endpoints, or loopback — bypassing network segmentation. The existing `ssrf_basic` flag is declared but unimplemented. Phase 12 implements it.

## 2. Threat model

**Attacker capability:** control over a request field that 7Guard uses to determine the upstream target or an internal fetch URL (e.g., a header, query param, or config-driven upstream). Goal: reach internal resources (metadata, databases, admin panels) that are not exposed externally.

**Enforcement boundary:** 7Guard validates every outbound dial it initiates against a blocklist of sensitive IP ranges and hostnames. This is complementary to egress control (allowlist of known hosts) — SSRF protection is deny-list based (block dangerous destinations regardless of allowlist), egress is allow-list based (permit only known destinations).

**Interaction order:** SSRF check runs **before** egress allowlist evaluation. A request targeting a blocked range is rejected even if the host is in the egress allowlist.

## 3. Goals

- Resolve DNS first, validate the resolved IP, then dial the validated IP (resolve-validate-dial). No re-resolution on redirect.
- Block private, loopback, link-local, CGNAT, ULA, and cloud-metadata ranges by default.
- Normalize IPv4-mapped IPv6 (`::ffff:127.0.0.1`) before range checks.
- Detect mode: allow + log + metric (default for initial rollout).
- Block mode: deny the connection; return 502 to caller.
- Fail-closed: DNS resolution failure → block.
- Validate every hop in a redirect chain.

## 4. Non-goals

- Full network policy replacement (infrastructure-level).
- Controlling the backend's own outbound traffic.
- DNSSEC validation (out of scope; rely on resolver).

## 5. Configuration

```yaml
ssrf:
  mode: detect          # off | detect | block
  blocked_ranges:        # additional CIDRs to block (merged with defaults)
    - 10.0.0.0/8
  allowed_hosts:         # hostnames exempt from SSRF checks (for internal backends)
    - internal-api.local
  block_metadata: true   # block cloud metadata endpoints (default true)
```

**Defaults:** `mode: detect`, `block_metadata: true`, blocked ranges = RFC 1918 + loopback + link-local + CGNAT + ULA + metadata endpoints.

**Feature flag:** `ssrf_basic` (Standard+ profile, default-on in Full+).

## 6. Blocked ranges (default)

| Range | Description |
|-------|-------------|
| `127.0.0.0/8` | IPv4 loopback |
| `::1/128` | IPv6 loopback |
| `::ffff:127.0.0.0/104` | IPv4-mapped loopback |
| `10.0.0.0/8` | RFC 1918 |
| `172.16.0.0/12` | RFC 1918 |
| `192.168.0.0/16` | RFC 1918 |
| `169.254.0.0/16` | Link-local (incl. 169.254.169.254 metadata) |
| `fe80::/10` | IPv6 link-local |
| `100.64.0.0/10` | CGNAT |
| `fc00::/7` | IPv6 ULA |
| `169.254.169.254/32` | AWS/GCP/Azure metadata (IPv4) |
| `fd00:ec2::254/128` | AWS metadata (IPv6) |
| `100.100.100.200/32` | Alibaba metadata |
| `metadata.google.internal` | GCP metadata hostname |

## 7. Resolve-validate-dial pattern

```
func checkSSRF(ctx, host) (net.IP, error) {
    ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
    if err != nil {
        return nil, err  // fail-closed
    }
    for _, ip := range ips {
        normalized := normalizeIP(ip)  // unwrap IPv4-mapped
        if isBlocked(normalized) {
            return nil, ErrBlocked
        }
    }
    return ips[0], nil  // dial this IP, not re-resolve
}
```

**Key invariants:**
- DNS is resolved once per request; the resolved IP is dialed directly (no re-resolution).
- On redirect, re-resolve and re-validate the new target.
- Cache resolution result for request duration (prevent TOCTOU).

## 8. IPv6-mapped normalization

```go
func normalizeIP(ip net.IP) net.IP {
    if v4 := ip.To4(); v4 != nil && ip.To16() != nil && !ip.Equal(v4) {
        // IPv4-mapped IPv6: ::ffff:x.x.x.x
        return v4
    }
    return ip
}
```

## 9. Redirect handling

- `CheckRedirect` on internal `http.Client` re-validates each redirect target.
- Redirects to blocked ranges are rejected (return error).
- Maximum 3 redirects (prevent infinite loops).

## 10. Observability

- Log: `SSRF: {request_id, target_host, resolved_ip, action, reason, mode}`
- Metric: `ssrf_block_total` counter (by reason: blocked_range, metadata, dns_failure, redirect_blocked).
- No secrets or full URLs in logs.

## 11. Acceptance criteria

1. IP literal `127.0.0.1` → blocked in block mode, logged in detect mode.
2. IP literal `::1` → blocked.
3. IP literal `::ffff:127.0.0.1` → normalized to `127.0.0.1` → blocked.
4. Hostname resolving to `10.0.0.1` → blocked (DNS rebinding).
5. Redirect to internal IP → blocked.
6. Metadata endpoint `169.254.169.254` → blocked.
7. Private range `192.168.1.1` → blocked.
8. Allowlist override → host in `allowed_hosts` skips check.
9. Detect mode → allow + log + metric.
10. Block mode → 502 + log + metric.
11. DNS failure → block (fail-closed).
12. Non-private public IP → allowed.

## 12. Test matrix (pitfalls)

- IPv4-mapped IPv6 normalization.
- DNS rebinding (hostname → private IP).
- Redirect chain (3 hops, last to internal).
- Metadata endpoints (all 3).
- CGNAT range (100.64.x.x).
- IPv6 ULA (fc00::/7).
- Allowlist override.
- Detect vs block mode.
- Fail-closed on DNS error.
- Concurrent requests (race).

## 13. Implementation plan

1. Create `internal/ssrf` package: `IsBlocked(ip)`, `NormalizeIP(ip)`, `Check(host) (ip, error)`, `BlockedRanges()`.
2. Wire into proxy: `DialContext` wrapper that calls `ssrf.Check` before dialing.
3. Add `CheckRedirect` to internal `http.Client`.
4. Config: `SSRFMode`, `SSRFBlockedRanges`, `SSRFAllowedHosts`, `SSRFBlockMetadata`.
5. Metrics: `ssrf_block_total` counter.
6. Feature flag: `ssrf_basic` (Standard+).
7. Tests: `internal/ssrf/*_test.go` + `internal/proxy/phase12_test.go`.

## 14. Open questions

1. Should SSRF check apply to the upstream dial only, or all outbound fetches? (Recommendation: all outbound dials via the shared `DialContext`.)
2. Should `allowed_hosts` support wildcards? (Recommendation: yes, `*.internal.local`.)
3. Should metadata blocking be on by default even in detect mode? (Recommendation: yes, detect mode logs but the range is still evaluated.)

---

**@viola** — please review against your 8 points. **@astra-ox-github** — open PR once approved.