# Response Body Inspection / Data-Leakage Detection — Design Document

**Status:** Draft (pending review)
**Owner:** SatriaBagusNurhadianto
**Related:** `FEATURES.md` (Full+ profile, `response_inspection` feature flag), `internal/detector` (request-side inspection), `internal/metrics`

## 1. Problem statement

7Guard inspects *inbound requests* for SQLi, XSS, traversal, etc. It does not inspect *outbound responses*. A backend can leak sensitive data through responses: PII (emails, phone numbers, SSNs, credit cards), secrets (API keys, tokens, private keys), or error-page leakage (stack traces, SQL errors, internal paths). Such leaks happen silently and are invisible to the request-side WAF. Response body inspection closes this gap.

## 2. Threat model & enforcement boundary

**Scope: (a) — what 7Guard can see on the response path.** 7Guard sits between client and backend, so it can observe and modify responses. It cannot control what the backend *logs* or *stores*; that is application/infrastructure-level. Documenting this boundary avoids a false promise.

**Enforcement point:** a response-body wrapper on the reverse proxy's `ServeHTTP` path, applied after the upstream response is received and before bytes are written to the client. All response bodies pass through this gate when the feature is enabled.

**Trust boundary:** the upstream backend is semi-trusted; the client is untrusted. Response inspection protects the *client* from backend leakage, not the backend from the client.

## 3. Goals

- Detect PII, secrets, and error-page leakage in response bodies.
- Detect mode: allow + log + metric (default for initial rollout).
- Block mode: strip/replace the sensitive content, or return 502 (configurable).
- Size-bounded: never buffer unbounded response bodies (stream or cap at N bytes).
- Content-Type gating: only inspect `text/*` and `application/json`; skip binary to avoid corruption.
- Reuse existing metrics package; add `response_leak_total` counter by type.

## 4. Non-goals

- Full DLP suite (no document classification, no exact-data matching against a user database).
- Inspecting compressed responses without decompression (see §7).
- Modifying response headers beyond Content-Length when body is altered.
- Controlling backend logging/storage (out of scope; see §2).

## 5. Configuration

```yaml
response_inspection:
  mode: detect          # detect | block
  max_body_bytes: 1048576  # 1 MiB cap; larger bodies are scanned up to cap then passed through
  content_types:        # optional override; defaults to text/* + application/json
    - "text/*"
    - "application/json"
  on_leak: strip        # strip | replace | block (block mode only)
  replace_token: "[REDACTED]"
```

- `ResponseInspectionMode` defaults to `detect`.
- `ResponseInspectionMaxBodyBytes` defaults to 1 MiB.
- `on_leak` only applies in block mode; detect mode always allows + logs + metric.
- Config validation at load time: reject negative max bytes, unknown mode/on_leak; fail-closed on invalid.

## 6. Design: wrap-and-scan

A naive "read whole body, scan, write" OOMs on large responses. The safe pattern:

1. **Gate on Content-Type.** If the response Content-Type does not match the configured list (after media-type parsing, ignoring parameters), pass through untouched (stream).
2. **Cap the body.** Read up to `max_body_bytes` into a buffer; if the body exceeds the cap, scan the prefix and pass the remainder through unscanned (log a `truncated` flag). Never buffer more than the cap.
3. **Scan** the buffered prefix with the leakage detectors (PII regex, secret patterns, error-page signatures).
4. **Act on findings:**
   - Detect mode: allow body, emit `response_leak_total{type=...}` and a structured log record; pass through.
   - Block mode with `strip`: remove matched spans from the body, adjust Content-Length, pass through.
   - Block mode with `replace`: replace matched spans with `replace_token`.
   - Block mode with `block`: return 502 to the client, discard body.
5. **Write** the (possibly modified) body to the client with correct Content-Length (or chunked if original was chunked and we didn't alter length).

**Streaming vs. buffering:** v1 buffers up to the cap (simplest correct). True streaming (scan as bytes arrive) is a v2 optimization. Document this limitation.

## 7. Content handling

### Content-Type gating

Only inspect when the response `Content-Type` media type matches one of:
- `text/*` (text/plain, text/html, text/css, text/javascript, ...)
- `application/json`, `application/xml`, `application/javascript`

Skip (pass through byte-for-byte): `image/*`, `application/pdf`, `application/octet-stream`, `application/gzip`, etc. Binary corruption is unacceptable.

### Compression

Responses may be gzip/deflate encoded. v1 options:
- **Skip compressed responses** (pass through unscanned) — simplest, no corruption risk, but misses leaks in compressed bodies.
- **Decompress, scan, re-encode** — more complete but adds complexity and CPU cost; risk of breaking framing.

Recommendation for v1: skip compressed responses (pass through) and log `skipped_compressed`. Revisit in v2 with a streaming decompressor. Document this limitation in §4.

### Redirect responses (3xx)

Pass through unmodified: do not scan the (usually empty) body, do not alter Location header, do not change status. Redirect handling is the client's concern.

### Error responses (4xx/5xx)

Scan the body (error pages often leak stack traces) but preserve the status code and headers. Block mode may strip/replace but must not change 4xx/5xx to 200 or 502 (except explicit `block` action, which returns 502).

### Truncated / partial body

If the upstream closes mid-body, scan what we have, pass it through, log `truncated=true`. No crash.

## 8. Observability

New metrics (added to `internal/metrics`):
- `response_leak_total` (counter, by type: `pii`, `secret`, `error_page`). Increments **once per response per leak type** (a page with 10 emails → +1 `pii`, not +10).

Structured log record per leak decision: request_id, response_status, content_type, leak_type, action, truncated. No leaked content in logs (log the *type* and *location*, never the matched secret).

## 9. Acceptance criteria (QA)

1. PII detection: emails, phone numbers, SSNs, credit cards (Luhn-validated) in response body → leak recorded.
2. Secret detection: API keys, bearer tokens, private-key headers → leak recorded.
3. Error-page detection: stack traces, SQL errors, internal paths → leak recorded.
4. Detect vs. block modes: detect allows + logs + metric; block strips/replaces or returns 502.
5. Size cap: body > `max_body_bytes` → scan prefix, pass remainder, log `truncated`.
6. Content-Type gating: only text/* + application/json scanned; binary passes byte-for-byte.
7. Compressed responses: passed through unscanned (v1), logged `skipped_compressed`.
8. Redirect responses (3xx): passed through unmodified.
9. Error responses (4xx/5xx): scanned, status code preserved (except explicit block).
10. Truncated body: no crash, partial scan, pass-through.
11. No false positives on legitimate content (e.g., a page that legitimately contains an email): in detect mode the email is *recorded* (metric + log) but *allowed* (not blocked). "No false positive" means "not incorrectly blocked / not breaking functionality," not "not detected."
12. Memory: peak RSS does not grow with response body size beyond the cap.

## 10. Security pitfalls & required tests

| Pitfall | Test |
|---|---|
| Unbounded buffering | 100 MiB response → peak memory ≤ cap + small overhead |
| Binary corruption | PNG response → byte-for-byte identical output |
| Compressed body | gzip response → passed through, `skipped_compressed` logged |
| Truncated body | upstream closes mid-stream → no panic, partial scan |
| Redirect bypass | 302 with Location → unmodified |
| Status preservation | 500 with stack trace → status stays 500 in detect mode |
| False positive | page with legitimate email → no leak in detect mode? (configurable; default: record but allow) |
| Block mode strip | secret in body → stripped, Content-Length updated |
| Block mode 502 | `on_leak=block` → 502 returned, body discarded |
| Credit card Luhn | invalid Luhn number → not flagged |
| Secret in log | matched secret never appears in structured log |

## 11. Implementation plan (after design approval)

1. `internal/leakage` (or extend `internal/detector`): `Scanner` with PII/secret/error-page detectors, `Scan(body []byte) []Leak`.
2. Config: `ResponseInspectionMode`, `ResponseInspectionMaxBodyBytes`, `ResponseInspectionContentTypes`, `OnLeak`, `ReplaceToken`, validation.
3. Proxy wiring: wrap response body in `ServeHTTP`; apply size cap + Content-Type gate + scan + action.
4. Metrics: `response_leak_total` counter by type.
5. Structured log record per leak (request_id, status, content_type, leak_type, action, truncated).
6. Tests: unit (each detector, Luhn, normalization) + integration (detect/block, size cap, content-type, compressed, redirect, truncated, memory).
7. `FEATURES.md`: response inspection stays Full+ (already listed).

### Implementation notes (from QA design review)

1. **Memory bound test:** use `runtime.MemStats` (HeapAlloc/Alloc), not OS RSS; assert peak allocation ≤ 2× cap.
2. **Content-Type parsing:** use `mime.ParseMediaType` to extract media type, ignoring parameters (`application/json; charset=utf-8` → `application/json`).
3. **Regex compilation:** compile all PII/secret/error-page patterns once at init; compiled regexes are safe for concurrent use. Scanner must not mutate shared state.
4. **Block mode Content-Length:** update `Content-Length` when stripping/replacing; if original was chunked, use chunked encoding for the modified body. Test both cases.

## 12. Open questions

- Should response inspection be gated behind `HasFeature("response_inspection")` (Full+) or always available? Recommendation: feature-gated, default off for Lite.
- Should `on_leak=strip` remove the matched span entirely or replace with a token? Recommendation: configurable, default replace with `[REDACTED]`.
- Should credit-card detection require Luhn validation? Recommendation: yes, to reduce false positives.
- v1 skips compressed responses; is that acceptable? Recommendation: yes, document as limitation; v2 adds streaming decompression.

## 13. Review checklist

- [ ] Threat model & boundary agreed
- [ ] Acceptance criteria agreed
- [ ] Security pitfalls covered by tests
- [ ] Config validation fail-closed
- [ ] Memory bound verified (cap enforced)
- [ ] Content-Type gating correct (binary untouched)
- [ ] Design approved before implementation
