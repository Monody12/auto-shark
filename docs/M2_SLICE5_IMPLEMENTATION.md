# M2 Slice 5 Implementation Plan

Status: approved and active as of 2026-08-13, Asia/Shanghai.

This document is the durable implementation contract for the next Auto-Shark
work. Read it after `PROJECT_STATE.md` and `docs/ROADMAP.md` when this slice is
active. Update the verification evidence in `PROJECT_STATE.md` after each
tested sub-slice.

## Scope and order

1. Correct the independently disproved JPEG acceptance hash.
2. Complete bounded static file signature scanning, structural validation,
   carving, artifact deduplication, trailing-data evidence, and schema upgrade.
3. Implement streaming TCP segment indexing and per-direction reconstruction
   with exact retransmission, overlap-conflict, and gap provenance.
4. Re-run unit, migration, Python 3.11, Python 3.9, real-sample, resource-bound,
   and idempotency checks before changing milestone status.

File carving is implemented now because it is needed to validate existing M2
HTTP evidence. General FTP/Telnet/file analysis remains M3 scope. TCP stream
reconstruction remains an M2 exit item.

## Revalidated sample facts

All five capture hashes match `docs/ACCEPTANCE_SAMPLES.md`.

- Telnet: stream 0 contains 36 data frames and 310 payload bytes, with no
  TShark retransmission, out-of-order, or lost-segment markers. Frame 41 is the
  cleartext candidate after the password prompt.
- HTTP form: frame 20 pairs with frame 26 and contains ordered fields `email`,
  `password`, and `captcha`. Across the capture TShark marks seven suspected
  retransmissions. Target stream 2 contains two 20-byte duplicate response
  segments and four one-byte same-sequence conflicting client segments.
- FTP: frame 55 links to PASV setup frame 44 and `RETR flag.rar` frame 49. Its
  164 bytes begin with RAR4 magic and hash to
  `941702f949e60d081210d33a98552b32d3e5b36673be2e6c0f439904f46b5597`.
- Multipart JPEG: frame 233 body length is 164,161. JPEG range is
  `[138, 164076)`, length 163,938, SHA-256
  `d8e9ba607bde8bccb1bf812e7d0d354abf41a57c0461e6b59c1fa9d5dcc58888`.
  Range `[164076, 164161)` contains 85 trailing bytes: the 38-byte flag-like
  value, one separator byte, CRLF, and the closing multipart boundary. Frame
  260 is HTTP 500 while its body contains `upload success`.
- WebShell: 19 `/upload/1.php` transactions are already indexed. Frame 1367
  body length is 230; ZIP range is `[3, 227)`, its central directory starts at
  absolute offset 93, EOCD starts at 183, EOCD comment length is 22, and three
  application-delimiter bytes follow it. The sole `flag.txt` member is
  encrypted and must not be read, decrypted, or extracted. Stream 0 contains
  three identical 1,380-byte retransmissions, for 4,140 duplicate bytes.

## File carving contract

- Scan fixed-size windows with signature-length overlap. Do not map or read an
  entire arbitrary-size blob into Python memory.
- Enforce positive scan-byte, candidate-count, and artifact-size limits.
- Validate PNG chunks through IEND; parse JPEG marker and entropy-coded regions
  through a legal EOI; validate ZIP EOCD, comment, central-directory offset and
  size without reading members; validate bounded PDF EOF. RAR, GZIP, and PE may
  remain `signature-only` with an explicit reason.
- Never execute, decrypt, unpack, render, or recursively open carved content.
- Persist exact parent evidence and `[start, end)` ranges. Prefix/trailing data
  remain range evidence over the parent blob. A carved file gets its own
  content-addressed blob.
- Deduplicate artifacts by content hash while retaining every source evidence
  link. Repeated carving must not change stable row counts.
- A scan limit that prevents end validation must produce an explicit bounded or
  unvalidated result, not silently scan beyond the configured budget.

## TCP reconstruction contract

- Capability-detect every requested TShark field. Structured fields are the
  primary contract; Follow Stream output is diagnostic only.
- Stream segment metadata line by line. Store direction, frame, raw sequence,
  relative sequence basis, payload length/hash, flags, and available TShark
  anomaly markers without accumulating capture output in RAM.
- Reconstruct client-to-server and server-to-client sequence spaces separately.
  Exact duplicate bytes are discarded with provenance. Differing overlap bytes
  create an `overlap-conflict` record and a deterministic first-seen output;
  they are never silently treated as identical. Missing sequence ranges create
  explicit gap records.
- Stream reconstructed bytes to the content-addressed blob store and persist
  mappings from each output range to all contributing frame ranges. Mark
  partial, conflicting, capture-midstream, SYN/FIN/RST, and truncation state.
- Enforce per-direction and total reconstruction byte budgets and persist every
  skipped or truncated state.

## Required verification

- Migration tests from every supported schema, foreign-key checks, stable IDs,
  and unknown-newer-schema rejection.
- File parser tests for false signatures, nonzero offsets, truncation, ZIP
  comments and prepended bytes, JPEG stuffed bytes and false EOI patterns,
  duplicate artifact provenance, large sparse/input files, and idempotency.
- TCP tests for direction isolation, exact retransmission, partial overlap,
  conflicting overlap, gaps, capture-midstream sequence bases, and budgets.
- Real frame 233 JPEG/trailing evidence, frame 1367 ZIP/application delimiters,
  FTP frame 55 RAR metadata, HTTP form conflict evidence, and WebShell duplicate
  retransmission evidence.
- Ruff, Python 3.11 coverage, and Python 3.9 tests. Runtime `jobs` directories
  remain empty. No captured content is executed or unpacked.
