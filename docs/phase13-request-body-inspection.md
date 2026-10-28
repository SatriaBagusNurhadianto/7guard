# Request Body Inspection — Design Document (Phase 13)

**Status:** Draft (pending review)
**Owner:** SatriaBagusNurhadianto
**Related:** `FEATURES.md` (Full+ profile), `internal/detector` (existing injection detection), `internal/leakage` (response inspection), `docs/streaming-decompression.md` (Phase 11)

## 1. Problem statement

7Guard inspects inbound request paths (URL, headers) via `internal/detector` and response bodies via `internal/leakage`, but it has no dedicated request-body inspection. An attacker can embed SQLi/XSS/command-injection payloads in POST bodies, upload oversized payloads (DoS), or use content-type confusion to bypass the detector. Phase 13 adds inbound request-body scanning.

## 2. Threat model

**Attacker capability:** control over the request body (POST/PUT/PATCH). Goal: inject payloads that reach the backend, exhaust proxy memory (DoS), or bypass content-type checks.

**Enforcement point:** `http.Server` handler / reverse-proxy director — scan the body before forwarding. Detect mode logs + allows; block mode rejects with 400/413.

## 3. Goals

- Size cap on decompressed body (bounded memory, `io.LimitReader`).
- Content-Type gating (reuse `contentTypeAllowed` helper; binary pass-through by default).
- Detect mode: log + metric, pass through.
- Block mode: return 400/413 + log + metric.
- Compressed request bodies (`Content-Encoding: gzip/deflate`): reuse Phase 11 decompression (single encoding, zip-bomb guard, corrupt → pass through).
- Multipart: scan raw body for injection patterns (simpler, consistent with detector).
- Fail-closed: body read failure → block in block mode.
- No strip/replace (can't modify client request).

## 4. Non-goals

- Full WAF rule engine (use existing detector rules).
- File content scanning (malware) — out of scope.
- Request body rewriting.

## 5. Configuration

```yaml
request_inspection:
  mode: detect          # off | detect | block
  max_body_bytes: 1048576  # applies to decompressed output
  content_types: []      # empty = defaults (text/*, json, xml, js)
  decompress: true      # scan compressed request bodies
```

**Feature flag:** `request_inspection` (Full+ profile, default-off except infrastructure).

## 6. Size cap & streaming

- `MaxRequestBodyBytes` applies to **decompressed** output (mirror Phase 11).
- Use `io.LimitReader(req.Body, maxBytes+1)` — read up to maxBytes+1 to detect truncation.
- If body exceeds cap: block mode → 413 Payload Too Large; detect mode → pass through with `truncated=true` logged.
- Never buffer full body; stream through.

## 7. Content-Type gating

Reuse `contentTypeAllowed(cfg, mediaType)` from Phase 11. Default: `text/*`, `application/json`, `application/xml`, `application/javascript`. Binary types (images, PDFs, octet-stream) pass through unscanned.

## 8. Compressed request bodies

Reuse Phase 11 decompression logic:
- Single encoding (`gzip`, `deflate`): decompress + scan.
- Multi-encoding: pass through (log `skipped_multi_encoding`).
- Zip-bomb guard: ratio > 100:1 → pass through + log `zip_bomb_suspected`.
- Corrupt/truncated → pass through + log.
- `decompress: false` → preserve Phase 10 skip behavior.

## 9. Injection detection

- Call `detector.Scanner.Scan()` on the request body bytes.
- The detector already runs on URL/headers (existing pipeline). Request body inspection adds body-level scanning only — no duplication.
- Detect mode: log + metric (`request_injection_total` by type), pass through.
- Block mode: return 400 + log + metric.

## 10. Detect vs block

| Mode | On injection | On oversized | On corrupt |
|------|-------------|-------------|------------|
| detect | log + metric, pass through | pass through + truncated log | pass through + log |
| block | 400 + log + metric | 413 + log | pass through + log (fail-open on corrupt) |

No strip/replace (can't modify client request).

## 11. Observability

- Log: `REQUEST_INSPECT: {request_id, content_type, types, action, truncated, content_encoding, decompressed}`
- Metric: `request_injection_total` counter by type (sqli, xss, cmd, etc.).
- No request body content in logs.

## 12. Acceptance criteria

1. Oversized body (> cap) → 413 in block mode.
2. Oversized body → pass-through + `truncated=true` in detect mode.
3. Binary content-type → pass through unscanned.
4. Compressed body (gzip) → decompress + scan.
5. Multi-encoding → pass through (logged).
6. Zip bomb → pass through + `zip_bomb_suspected`.
7. Corrupt gzip → pass through + `skipped_corrupt`.
8. Detect mode → log + metric, pass through.
9. Block mode → 400 + log + metric.
10. Multipart → scan raw body.
11. Fail-closed: body read error → block in block mode.
12. Plain regression: detector still runs on URL/headers.

## 13. Test matrix (pitfalls)

- Streaming memory bound (peak alloc ≤ 2× cap).
- Content-Type gating (binary pass-through).
- Compressed request body (gzip decompress + scan).
- Multipart (text fields scanned).
- Detect vs block mode.
- Corrupt gzip, truncated gzip.
- Zip bomb.
- Oversized → 413 (block) / pass-through (detect).
- Fail-closed on I/O error.
- Concurrent requests (race).

## 14. Implementation plan

1. Add config fields: `RequestBodyInspectionMode`, `RequestBodyMaxBytes`, `RequestBodyContentTypes`, `RequestBodyDecompress`.
2. Add feature flag `request_inspection` (Full+).
3. Implement in proxy: wrap `req.Body` with inspection reader before forwarding.
4. Reuse `contentTypeAllowed`, Phase 11 decompression.
5. Call `detector.Scanner.Scan()` on body bytes.
6. Metrics: `request_injection_total` counter.
7. Tests: `internal/proxy/phase13_test.go`.

## 15. Open questions

1. Should request body inspection run before or after rate limiting? (Recommendation: after rate limiting, before forwarding.)
2. Should multipart file parts be skipped? (Recommendation: scan raw body regardless — simpler, consistent with detector.)
3. Should we support `application/x-www-form-urlencoded`? (Recommendation: yes, scan as text.)

---

**@viola** — please review against your 10 points. **@astra-ox-github** — open PR once approved.