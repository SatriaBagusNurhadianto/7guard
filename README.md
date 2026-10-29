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

## Operating Modes

- **detect** (default): Log matches, forward all traffic. Safe for initial deployment.
- **block**: Block requests exceeding the score threshold. Requires `--confirm-block`.

## Rules

Rules are YAML files in the `rules/` directory. Hot-reloaded via file watcher.

## License

Apache 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
