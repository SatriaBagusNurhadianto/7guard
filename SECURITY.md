# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x (current) | ✅ |
| < 0.1 | ❌ |

## Reporting a Vulnerability

7Guard is a security tool — we take vulnerabilities seriously.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please report via:
- **GitHub Security Advisories**: Use the "Report a vulnerability" button on the [Security tab](https://github.com/SatriaBagusNurhadianto/7guard/security)
- **Email**: Contact the maintainer directly

### What to include
- Description of the vulnerability
- Steps to reproduce
- Affected version/profile
- Impact assessment (what an attacker could achieve)
- Suggested fix (if any)

### Response timeline
- **Acknowledgment**: within 48 hours
- **Initial assessment**: within 7 days
- **Fix or mitigation**: within 30 days for Critical/High, 90 days for Medium/Low

### Scope
In scope:
- 7Guard engine (proxy, detection, rate limiting, TLS, JWT)
- All deployment profiles (Lite, Full, Advanced, Maximum)
- Docker Compose deployment configurations

Out of scope:
- Vulnerabilities in upstream dependencies (report to the dependency maintainer)
- Issues in the dummy/test upstream services
- Social engineering attacks

### Disclosure policy
We follow coordinated disclosure. Please allow us time to fix before public disclosure. We will credit reporters in release notes (unless anonymity is requested).

## Security design
- Detection-first mode by default (`--mode=detect`) — never blocks without explicit opt-in
- Profile gating enforced at config load + feature invocation (defense-in-depth)
- No secrets in repository (enforced by secret scanning + push protection)
- All user input is validated with strict allowlists
- Single-decode normalization prevents double-encoding bypasses
- Overlong UTF-8 normalization prevents encoding bypasses