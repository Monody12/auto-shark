# M3 Slice 1 FTP Implementation Contract

Status: complete and verified as of 2026-08-13, Asia/Shanghai.

This slice adds capability-gated FTP control/data correlation and bounded
static transfer export without opening transferred content.

## Verified sample facts

- Capture SHA-256 remains
  `0f2d01cbc13028deab3af0e105bba33f13fcbe3195e726dceaf0dcd7ea257c98`.
- Control TCP stream 3 has one transfer sequence: PASV request frame 42, `227`
  passive response frame 44 (`172.16.66.10:14438`), `RETR flag.rar` frame 49,
  preliminary `150` frame 51, and completion `226` frame 66.
- FTP-DATA TCP stream 4 has one payload frame, frame 55. TShark 4.6.7 exposes
  `ftp-data.setup-frame=44`, `setup-method=PASV`, `command-frame=49`, and
  `command=RETR flag.rar`; correlation does not need stream-order guessing.
- Frame 55 payload is exactly 164 bytes, starts with RAR4 magic, and hashes to
  `941702f949e60d081210d33a98552b32d3e5b36673be2e6c0f439904f46b5597`.
  It has no TShark retransmission, spurious-retransmission, out-of-order, or
  lost-segment marker.

## Structured adapter contract

- `protocols/ftp.py` uses TShark field output only. Required semantic fields
  include FTP request/response fields plus FTP-DATA setup frame, setup method,
  command frame, and command. IP endpoint capability may be IPv4 or IPv6.
- Metadata is streamed line by line with bounded line/stderr/time limits.
  Protocol messages retain frame/time/endpoints/TCP stream/direction and the
  exact structured fields used for correlation.
- `ftp_message` stores control requests/responses. `ftp_data_message` stores
  data-frame setup/command references and payload length. Stable IDs are based
  on capture hash, protocol, frame, and message kind.
- A metadata message limit does not silently drop later frames: every parsed
  over-limit FTP/FTP-DATA frame gets an explicit skip record and summary count.

## Transfer and export contract

- `ftp_transfer` is keyed by capture, setup frame, command frame, data stream,
  and direction. It links the control/data messages, metadata tool run, current
  TCP reconstruction, exact `ftp-data` evidence, and optional artifact.
- Explicit TShark frame references are authoritative. Missing setup or command
  references produce `unresolved`, never a guessed relationship.
- Unique data streams are reconstructed through the existing bounded TCP
  engine. Transfer-count, metadata-count, segment-index, per-direction, and
  total-output budgets are positive and explicit. Transfers beyond a limit or
  remaining output budget persist as `skipped-limit` or `skipped-budget`.
- Only a complete, gap-free, conflict-free, untruncated current reconstruction
  in the FTP-DATA direction becomes whole-range `ftp-data` evidence. Partial,
  conflicting, truncated, empty, failed, or unresolved transfers remain
  auditable but do not create a misleading artifact.
- Export reuses the reconstruction content-addressed blob; it does not copy
  large bytes into SQLite. Suggested filenames are reduced to a basename and
  stripped of control/path characters. RAR4 may be classified by magic only.
- The artifact is queued `unreviewed`. Auto-Shark must not open, list, extract,
  decrypt, crack, render, or execute the transferred content.
- Repeated indexing/reconstruction preserves stable message, transfer,
  evidence, artifact, and link rows. Tool-run provenance may append.

## CLI and verification

- `auto-shark index-ftp <project> --tshark <path>` operates on an existing
  machine-local project and emits `auto-shark.ftp-index/v1` JSON with metadata,
  transfer/status, byte, artifact, skip, and limit counts.
- Tests cover field capability selection, line parsing, IPv4/IPv6 endpoints,
  explicit correlation, missing references, filename sanitization, RAR magic,
  transfer/message/output budgets, TCP partial/conflict states, migration,
  idempotency, CLI forwarding, and empty jobs cleanup.
- Real acceptance must prove frames 44/49/55, stream 4 direction, 164-byte hash,
  stable repeated rows, completed tool runs, blob rehash, foreign keys,
  integrity, and empty jobs. The adjacent answer file is never read.

All implementation and acceptance gates passed. Exact test commands, real row
counts, frame/direction/range/hash evidence, budget behavior, and runtime
integrity results are recorded in `PROJECT_STATE.md`.
