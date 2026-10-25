# Contributing to 7Guard

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/<you>/7guard.git`
3. Create a branch: `git checkout -b feat/your-feature`
4. Make your changes
5. Run tests: `go test ./... && go vet ./... && gofmt -l .`
6. Commit using [Conventional Commits](https://www.conventionalcommits.org/)
7. Push and open a PR

## Code Style

- All Go code must pass `gofmt` (zero unformatted files)
- All code must pass `go vet ./...`
- New features must include tests
- Security-sensitive changes require review from @SatriaBagusNurhadianto

## Adding Rules

Rules are YAML files in `rules/`. Each rule must have:
- `id`: unique identifier (kebab-case)
- `category`: rule category (sqli, xss, traversal, etc.)
- `severity`: critical, high, medium, low
- `pattern`: regex pattern (case-insensitive by default)
- `locations`: where to match (path, query, body, headers)
- `description`: human-readable description

## Profiles

Every PR that adds a feature must state which profile(s) it targets (lite/full/advanced/max). Update `FEATURES.md` accordingly.

## Security

- Never commit secrets or credentials
- Report security vulnerabilities via GitHub Security Advisories, not public issues
- All PRs are scanned with gosec and govulncheck in CI

## License

By contributing, you agree that your contributions will be licensed under the Apache License, Version 2.0.