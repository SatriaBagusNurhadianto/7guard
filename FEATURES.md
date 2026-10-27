# 7Guard Feature Matrix

Single source of truth for what's in each deployment profile.
PRs adding features must update this file.

## Profile Comparison

| Feature | Lite | Full | Advanced | Maximum |
|---------|------|------|----------|---------|
| TLS termination | ✅ | ✅ | ✅ | ✅ |
| Reverse proxy | ✅ | ✅ | ✅ | ✅ |
| Backend isolation | ✅ | ✅ | ✅ | ✅ |
| Basic WAF (SQLi, XSS, traversal) | ✅ | ✅ | ✅ | ✅ |
| IP filtering | ✅ | ✅ | ✅ | ✅ |
| Rate limiting | ✅ | ✅ | ✅ | ✅ |
| JWT security | ✅ | ✅ | ✅ | ✅ |
| Basic SSRF protection | ✅ | ✅ | ✅ | ✅ |
| Bounded logging | ✅ | ✅ | ✅ | ✅ |
| Secure configuration | ✅ | ✅ | ✅ | ✅ |
| Basic security events | ✅ | ✅ | ✅ | ✅ |
| Deeper inspection | ❌ | ✅ | ✅ | ✅ |
| Advanced WAF | ❌ | ✅ | ✅ | ✅ |
| Authorization policies | ❌ | ✅ | ✅ | ✅ |
| BOLA/IDOR enforcement | ❌ | ✅ | ✅ | ✅ |
| Advanced SSRF protection | ❌ | ✅ | ✅ | ✅ |
| Async alerting | ❌ | ✅ | ✅ | ✅ |
| Richer event processing | ❌ | ✅ | ✅ | ✅ |
| Stronger isolation | ❌ | ✅ | ✅ | ✅ |
| Egress-control integration | ❌ | ✅ | ✅ | ✅ |
| Behavioral signals | ❌ | ✅ | ✅ | ✅ |
| Response body inspection | ❌ | ✅ | ✅ | ✅ |
| Behavioral analysis | ❌ | ❌ | ✅ | ✅ |
| Attack-chain correlation | ❌ | ❌ | ✅ | ✅ |
| Session analysis | ❌ | ❌ | ✅ | ✅ |
| Adaptive rate limiting | ❌ | ❌ | ✅ | ✅ |
| Extended security context | ❌ | ❌ | ✅ | ✅ |
| Advanced event correlation | ❌ | ❌ | ✅ | ✅ |
| Richer threat analysis | ❌ | ❌ | ✅ | ✅ |
| Multi-dim behavioral correlation | ❌ | ❌ | ❌ | ✅ |
| Extended attack-chain analysis | ❌ | ❌ | ❌ | ✅ |
| Quarantine | ❌ | ❌ | ❌ | ✅ |
| Advanced adaptive defense | ❌ | ❌ | ❌ | ✅ |
| Richer forensic context | ❌ | ❌ | ❌ | ✅ |
| Extended historical context | ❌ | ❌ | ❌ | ✅ |

## Resource Limits

| Profile | RAM | CPU |
|---------|-----|-----|
| Lite | 256M | 0.5 |
| Full | 512M | 1.0 |
| Advanced | 1G | 2.0 |
| Maximum | 2G | 4.0 |

## Phase 4 (Maximum profile) — wired

Behavioral analysis, quarantine, and adaptive defense are now wired into
the reverse proxy behind `HasFeature` (default-off). Feature flags are only
enabled for the `max` profile, so Lite/Full/Advanced behavior is unchanged.
Quarantine blocks quarantined clients; critical attack chains auto-quarantine
the subject; adaptive defense blocks on scores at/above the block threshold
in block mode. Adaptive throttling uses a consume-extra-token strategy (throttle consumes 2 tokens instead of 1 for immediate effect); the alternative refill-rate-halving semantics are not used. See `internal/ratelimit` (`AllowWithMultiplier`).

## Rate Limits (requests/minute)

| Profile | Rate | Burst |
|---------|------|-------|
| Lite | 60 | 10 |
| Full | 120 | 20 |
| Advanced | 300 | 50 |
| Maximum | 600 | 100 |
