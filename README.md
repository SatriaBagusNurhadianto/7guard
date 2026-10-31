# 7Guard

Open-source, self-hosted, origin-side security gateway. Protects backend applications from common web attacks, API abuse, and automated attacks.

## Operating modes

- **detect** (default): WAF rules log and score but do not block. Infrastructure controls (quarantine, rate limiting, JWT validation) still enforce — they are not WAF rules.
- **block**: WAF rules block matching requests (requires `--confirm-block`).

## Metrics endpoint

`/metrics` requires `--metrics-auth-token` (fail-closed). If unset, the endpoint returns 403.

```bash
# Build
go build -o 7guard ./cmd/7guard

# Run in detection mode (default, safe)
./7guard --profile=lite --mode=detect --upstream=http://localhost:9090

# Run in block mode (requires explicit confirmation)
./7guard --profile=lite --mode=block --confirm-block --upstream=http://localhost:9090
```

## Profiles

| Profile | RAM Target | Features |
|---------|-----------|----------|
| Lite | 1-2 GB | Basic WAF, rate limiting, JWT, SSRF basic, bounded logging |
| Full | 3-4 GB | + Advanced WAF, BOLA/IDOR, async alerting, egress control |
| Advanced | 5-7 GB | + Behavioral analysis, attack-chain correlation, session analysis |
| Maximum | 8 GB | + Multi-dim correlation, quarantine, adaptive defense |

## Security features

- **WAF rules**: YAML-driven, hot-reloaded; detector covers SQLi, XSS, traversal, and more.
- **Request body inspection**: bounded body (1 MB cap) with full body restored upstream.
- **SSRF protection**: blocked ranges (private, loopback, link-local, multicast, reserved, broadcast, IPv6) with DNS-rebinding safety via resolved-IP dialing.
- **Rate limiting** and **quarantine** (Maximum profile).
- **JWT validation** (optional, via `--jwt-secret`).
- **Trusted proxy / XFF handling**: fail-closed; spoofed XFF from untrusted peers is ignored.
- **Graceful shutdown**: in-flight requests drain on SIGTERM/SIGINT (10s window).
- **Request smuggling rejection**: ambiguous `Content-Length` + `Transfer-Encoding` rejected (400).
- **Slowloris protection**: `IdleTimeout` on keep-alive connections.
- **Oversized header protection**: `MaxHeaderBytes`.
- **Method allowlist**: applied to `/`, `/health`, and `/metrics`.
- **ReDoS mitigation**: per-rule regex timeout (100ms) with skip-and-log on timeout.
- **Double-decode + null-byte stripping** in the detector.
- **Metrics auth**: fail-closed (`--metrics-auth-token` required).

## Configuration

| Flag | Default | Description |
|------|---------|-------------|
| `--profile` | lite | Deployment profile (lite/full/advanced/max) |
| `--mode` | detect | Operating mode (detect/block) |
| `--confirm-block` | false | Required to enable block mode |
| `--listen` | :8080 | Listen address |
| `--upstream` | http://localhost:9090 | Upstream backend URL |
| `--max-body-size` | 1048576 | Max request body size in bytes |
| `--rules-dir` | ./rules | Directory containing YAML rule files |
| `--rate-limit` | 0 | Rate limit in requests per minute (0 = profile default) |
| `--trusted-proxies` | (none) | Comma-separated trusted proxy IPs/CIDRs for XFF |
| `--metrics-auth-token` | (none) | Bearer token for /metrics (empty = disabled/403) |
| `--idle-timeout` | 0 | Idle timeout in seconds (0 = use ReadTimeout) |
| `--max-header-bytes` | 1048576 | Max request header size in bytes |
| `--tls-cert` / `--tls-key` | (none) | Enable HTTPS |
| `--jwt-secret` | (none) | Enable JWT validation |
| `--quarantine-cleanup-interval` | 60 | Quarantine cleanup interval in seconds (0 = disabled) |

## Rules

Rules are YAML files in the `rules/` directory. Hot-reloaded via file watcher.

## Releases

Tagged releases (`v*`) are built automatically via GoReleaser: cross-platform binaries (linux/darwin/windows, amd64+arm64), sha256 checksums, and archives including rules. See `.github/workflows/release.yml` and `.goreleaser.yaml`.

## Development

```bash
make build        # go build ./...
make test         # go test -race ./...
make vet          # go vet ./...
make lint         # golangci-lint run ./...
make release-dry  # goreleaser snapshot build
```

CI runs gofmt, vet, tests (with -race), build, gosec, govulncheck, fuzz, docker smoke, and goreleaser config check on every PR.

## Progress

Recent slices:

- **Protection hardening**: idle timeout, max header bytes, request-smuggling rejection, method allowlist, detector double-decode + null-byte stripping.
- **ReDoS mitigation**: per-rule regex timeout (100ms) with skip-and-log.
- **Audit hardening**: detector body cap (LimitReader), SSRF range additions + mutex, fail-closed /metrics.
- **Trusted proxy / XFF**: fail-closed handling + graceful shutdown drain test.
- **Release pipeline**: GoReleaser + release workflow + Makefile.

## License

Apache 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
