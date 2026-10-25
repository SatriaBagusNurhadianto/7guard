# Contributing to 7Guard

Thank you for your interest in contributing to 7Guard!

## License

By contributing, you agree that your contributions will be licensed under the
Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

## How to Contribute

### Adding a Detection Rule

1. Add your rule to the appropriate YAML file in `rules/`
2. Follow the rule schema:
   ```yaml
   - id: category-descriptive-name
     category: sqli|xss|traversal|rate_limit|auth
     severity: low|medium|high|critical
     pattern: "regex pattern"
     locations: [query, body, path, header]
     description: "What this rule detects"
   ```
3. Add test cases: at least 3 attack payloads and 3 benign inputs
4. Run `go test ./...` to verify no false positives

### Adding a Detector

1. Create a new detector in `internal/detector/`
2. Implement the `Detect(*http.Request) []Match` interface
3. Add unit tests with attack + benign corpora
4. Ensure single-decode normalization is applied

### Profile Targeting

Every PR must state which profile(s) it targets in the PR description.
- Lite: basic features only
- Full: advanced features
- Advanced: behavioral analysis
- Maximum: full feature set

### Code Standards

- Run `gofmt -w .` before committing
- Run `go vet ./...` — must pass
- Run `go test ./...` — must pass
- Run `gosec ./...` — must have 0 issues
- All `.go` files should include the Apache 2.0 license header

### Pull Request Process

1. Fork the repo and create a feature branch
2. Make your changes
3. Ensure CI passes (gofmt, vet, test, build, gosec)
4. Open a PR with a clear description
5. Wait for review from a code owner

## Development Setup

```bash
git clone https://github.com/SatriaBagusNurhadianto/7guard.git
cd 7guard
go build ./...
go test ./...
```
