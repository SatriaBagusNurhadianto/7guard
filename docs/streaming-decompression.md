# Streaming Decompression for Compressed Responses — Design Document (Phase 11)

**Status:** Draft (pending review)
**Owner:** SatriaBagusNurhadianto
**Related:** `docs/response-inspection.md` (Phase 10), `FEATURES.md` (Full+ profile, `response_inspection` feature flag), `internal/leakage`, `internal/metrics`

## 1. Problem statement

Phase 10 skips compressed responses entirely (`Content-Encoding: gzip/deflate/br` → pass through unscanned, logged `skipped_compressed`). This means a backend can hide leaked PII/secrets behind compression and bypass the WAF. Phase 11 adds streaming decompression so compressed responses are inspected without buffering the full body or corrupting the response.

## 2. Threat model & enforcement boundary

Same as Phase 10 (§2): 7Guard sits between client and backend; it can observe/modify responses. Compressed responses are a transport encoding, not a security boundary — the leakage is still in the plaintext. Decompression must not become a DoS vector (memory/CPU).

## 3. Goals

- Inspect compressed response bodies (gzip, deflate, brotli) for data leakage.
- Stream decompression: do not buffer the full body; bounded memory.
- Preserve the original `Content-Encoding` contract with the client (re-encode after scan, or pass through transparently).
- Detect + block modes work on decompressed content.
- No crash on truncated/corrupt streams.

## 4. Non-goals (v1)

- Multi-encoding chains beyond 2 levels (e.g., `gzip, deflate, br`).
- Streaming block mode that strips in-flight (requires buffering the decompressed stream; see §7).
- Brotli in v1 unless `golang.org/x/compress` is available (stdlib has gzip/flate only).

## 5. Configuration

Reuses Phase 10 config. New field:

```yaml
response_inspection:
  decompress: true   # default true for Full+; false = Phase 10 behavior (skip compressed)
```

- `ResponseInspectionDecompress` defaults to `true` when feature enabled.
- If `false`, Phase 10 skip-compressed behavior is preserved.

## 6. Memory bound

**Hard cap: `max_body_bytes` (default 1 MiB) applies to the *decompressed* output, not the compressed input.**

- Decompress into a bounded buffer of `max_body_bytes`. If decompressed output exceeds the cap, stop decompressing, scan the prefix, and pass the remainder through unmodified (same as Phase 10 truncated handling).
- Never hold more than `max_body_bytes` of decompressed data in memory at once.
- Use `io.LimitReader` on the decompressor output.
- Peak allocation assertion: ≤ 2× cap (per QA note from Phase 10).

**CPU bound:** decompression is CPU-intensive. A maliciously compressed payload (zip bomb) can exhaust CPU. Mitigation: track decompressed/compressed ratio; if ratio exceeds a threshold (e.g., 100:1), abort and pass through unmodified (log `zip_bomb_suspected`). This is a heuristic, not a guarantee.

## 7. Content-Encoding chain

Support `Content-Encoding` values (in order, outermost first):

1. `gzip` — `gzip.NewReader`
2. `deflate` — `flate.NewReader` (raw deflate, no zlib header)
3. `br` — brotli (v2; skip in v1, pass through unscanned)

**Multi-encoding:** `Content-Encoding: gzip, deflate` means deflate then gzip (innermost first in the list is applied last). Parse the comma-separated list, apply decoders in reverse order.

**v1 scope:** single encoding (gzip or deflate). Multi-encoding chains are v2. If multiple encodings present, pass through unscanned (log `skipped_multi_encoding`).

## 8. Error handling

- **Truncated gzip stream:** `gzip.NewReader` returns `io.ErrUnexpectedEOF` on truncated input. Catch, scan what was decompressed, pass through (original compressed body) unmodified, log `truncated=true`.
- **Corrupt data:** `gzip.NewReader` returns error on invalid header. Pass through unscanned, log `skipped_corrupt`.
- **Unexpected EOF mid-stream:** scan prefix, pass through original compressed body, log `truncated=true`.
- **Never crash:** all decompression errors are caught and logged; proxy continues serving.
- **Never leak partial data in block mode:** if decompression fails mid-stream, do not emit a partially-stripped response; pass through original.

## 9. Interaction with block mode

**Problem:** Block mode (strip/replace) modifies the body. For compressed responses, modifying the decompressed body requires re-encoding (compress again) before sending to the client, or sending uncompressed (changing Content-Encoding).

**Options:**

| Option | Pros | Cons |
|---|---|---|
| A. Decompress → scan → strip/replace → re-compress | Full block-mode support | CPU cost, framing complexity, risk of corruption |
| B. Decompress → scan → if leak, block (502) or pass through original compressed | Simple, safe | Can't strip/replace in compressed responses; block mode becomes "block only" for compressed |
| C. Decompress → scan → strip/replace → send uncompressed (drop Content-Encoding) | Simple | Changes wire format; client may expect compressed |

**Recommendation (v1): Option B.** For compressed responses in block mode:
- Detect mode: scan decompressed, log + metric, pass original compressed body through.
- Block mode with `on_leak=block`: return 502 (same as Phase 10).
- Block mode with `on_leak=strip/replace`: pass through original compressed body unmodified (can't safely modify compressed stream), log `skipped_modification_compressed`. Document this limitation.

**v2:** Option A (re-compress) if demand warrants.

## 10. Observability

- Reuse `response_leak_total` (no new counter).
- Structured log adds `content_encoding` and `decompressed` (bool) fields.
- New log value: `skipped_compressed` (v1 skip path), `skipped_corrupt`, `truncated`, `zip_bomb_suspected`.

## 11. Acceptance criteria (QA)

1. Compressed (gzip) response with PII → detected, logged, metric incremented (detect mode).
2. Compressed response with PII → 502 returned (block mode, on_leak=block).
3. Compressed response with PII → original compressed body passed through unmodified (block mode, on_leak=strip/replace) + log `skipped_modification_compressed`.
4. Truncated gzip stream → no crash, prefix scanned, original passed through, `truncated=true`.
5. Corrupt gzip → pass through unscanned, `skipped_corrupt` logged.
6. Memory bound: decompressed body > cap → scan prefix, pass remainder, `truncated=true`. Peak alloc ≤ 2× cap.
7. Zip bomb (high ratio) → abort, pass through, `zip_bomb_suspected` logged.
8. Plain (uncompressed) response → Phase 10 behavior unchanged (regression).
9. `decompress: false` config → Phase 10 skip-compressed behavior (regression).
10. Content-Encoding header preserved on pass-through (no corruption).

## 12. Security pitfalls & required tests

| Pitfall | Test |
|---|---|
| Unbounded decompression (zip bomb) | 1MB gzip → 100MB output → abort, pass through, log |
| Memory exhaustion | Large compressed response → peak alloc ≤ 2× cap |
| Truncated stream | Truncated gzip → no panic, prefix scanned |
| Corrupt data | Invalid gzip bytes → pass through, `skipped_corrupt` |
| Multi-encoding | `gzip, deflate` → skip in v1 (pass through) |
| Block mode strip on compressed | Pass through unmodified, log `skipped_modification_compressed` |
| Content-Encoding corruption | Pass-through preserves header byte-for-byte |
| Regression (plain) | Uncompressed response still scanned (Phase 10) |
| Regression (decompress=false) | Skip-compressed behavior preserved |

## 13. Implementation plan (after design approval)

1. Add `ResponseInspectionDecompress` config field + validation.
2. `internal/leakage`: add `DecompressReader(encoding string, r io.Reader) (io.Reader, error)` helper.
3. Proxy `ModifyResponse`: if compressed and decompress enabled → wrap body in decompressor, apply size cap, scan, act per §9. If decompression fails → pass through original.
4. Metrics: reuse `response_leak_total`; add `content_encoding`/`decompressed` to structured log.
5. Tests: unit (decompressor helper, zip bomb detection) + integration (all §11 criteria).
6. `FEATURES.md`: no new feature row (enhancement to existing response inspection).
7. Update `docs/PROGRESS.md`.

## 14. Open questions

- Should brotli be supported in v1? Recommendation: no (stdlib lacks it; add in v2 with `golang.org/x/compress`).
- Should the zip-bomb ratio threshold be configurable? Recommendation: no, hardcode 100:1; document.
- Should block mode ever re-compress? Recommendation: no in v1 (Option B); revisit if demand.

## 15. Review checklist

- [ ] Memory bound agreed (cap on decompressed output)
- [ ] Encoding chain scope agreed (single in v1)
- [ ] Error handling agreed (no crash, pass through on failure)
- [ ] Block-mode interaction agreed (Option B)
- [ ] Test matrix agreed (§12)
- [ ] Design approved before implementation
