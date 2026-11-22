# Security hardening — rule set changes

This documents the rule changes in the hardened set. Every change is backed by a bypass
that was actually sent to a running 7Guard and observed, plus a false-positive measurement
against a benign traffic corpus.

## What changed

| File | Change |
|---|---|
| `rules/sqli.yaml` | 3 patterns widened, 4 rules gain `header` scanning, 7 rules added |
| `rules/xss.yaml` | 1 pattern widened, 3 rules gain `header` scanning, 2 rules added |
| `rules/traversal.yaml` | 1 rule gains `header` scanning |
| `rules/rce.yaml` | **new** — 2 command-injection rules |
| `rules/ssrf.yaml` | **new** — 1 request-parameter SSRF rule |

Net: 87 rules (was 75).

## Why these specific changes

**SQL injection.** The baseline patterns used `\s+` between keywords. Real SQL backends
accept other separators, and the detector strips `/**/` comments and null bytes, so
`uni/**/onselect`, `union%0bselect`, `union(select` and backtick/brace separators all
reached the application. The widened patterns accept the separator class
`[\s\x0b\x07\x1a\xa0]` and an optional parenthesis, and new rules cover hex literals,
`CHAR()` token building, `CONCAT(0x…)`, Oracle time/IO functions, glued keywords and
`%uXXXX` escapes.

**XSS.** `&lt;script` only caught one spelling of an encoded angle bracket. The new
pattern covers `&lt;`, `&gt;` and the numeric entities, and a new rule covers JS
`\u003c` / `\x3c` escapes. `details`-style handlers (`ontoggle`, `beforetoggle`, …) are
added because they fire without user interaction.

**Command injection — the important one.** The first attempt at an RCE rule was a
*denylist of command words* (`id|whoami|cat|wget|…`). It stopped the test corpus and then
let **every destructive command** through: `rm -rf`, `chmod -R 000`, `dd`, and a webshell
drop all executed. A denylist can never be complete.

`rce-shell-control` instead keys on the **shell control operator**:

```
(?:[;|`\r\n]|&&|\|\|)\s*\w+(?:[\s/'\"-]|$)
```

That catches `; rm -rf …`, `| id`, backticks and `%0a` chaining regardless of the command.
`rce-shell-metachain` is kept as a second layer for the common commands.

> A rule that listed destructive command words was tested and **rejected**: it produced
> false positives on 13 of 14 realistic benign strings (`how to echo hello in bash`,
> `use the cp command`, `linux kill process guide`, …). It is deliberately not included.

**SSRF.** The profile-level `ssrf_basic` check validates the address 7Guard dials, not
addresses supplied by the request. `ssrf-internal-url` covers parameters that point at
loopback, RFC1918 space or the cloud metadata range.

**Header scanning.** The detector has always built `locations["header"]` and
`locations["cookie"]`, but no rule declared them, so those inputs were never inspected.
Eight rules now scan headers.

## Verification

Run against a deliberately vulnerable application on the lab VM:

| Test | Result |
|---|---|
| Real-attack corpus (27 cases) | 25 blocked, 0 exploited |
| Destructive corpus (`rm -rf`, `chmod 000`, disk fill, webshell) | 7/7 blocked, 0 damage |
| Benign corpus (35 requests) | **0 false positives** |
| Protocol corpus (82 cases) | 64 blocked, 4 reached |

The 4 that still reach the application are `uni/**/on/**/sel/**/ect`,
`sl/**/eep(5)`, `information_schema.tables` and `union%A0select`. The first three need
comment-stripping-aware matching; the last needs NBSP decoding. They are recorded rather
than silently claimed fixed.

## Known residual / not covered

- `?q=rock;roll` is indistinguishable from `cmd;cmd` and will still be flagged by
  `rce-shell-control`. Inherent to pattern-based detection — the application must not
  pass user input to a shell.
- Header scanning joins header names and values with a space; a payload split across two
  header values will not match.
- Rules are matched against the decoded value, so double-encoded payloads that the
  application decodes a second time are outside this layer's visibility.
