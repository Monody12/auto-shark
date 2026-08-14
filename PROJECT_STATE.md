# Auto-Shark Project State

Updated: 2026-08-13, Asia/Shanghai

This is the canonical resume checkpoint. Update it after every tested slice.

## Objective

Deliver the v1 offline CTF packet-analysis workbench defined in `AGENTS.md` and
`docs/ARCHITECTURE.md`, with a Python 3.9+ CLI core, Windows/Python 3.11 GUI,
TShark structured parsing, bounded on-disk evidence processing, explainable
candidate ranking, static file analysis, and constrained optional Linux jobs.

## Current milestone

M3 - FTP, Telnet, files, and protocol/manual triage.

Status: active. M0, M1, and M2 exit criteria are complete.

The first M3 slice is active. Its FTP structured metadata, explicit frame
correlation, bounded TCP reuse, static export, and no-unpack contract is
recorded in `docs/M3_SLICE1_IMPLEMENTATION.md`. That slice is now complete.

The user approved the M3 directional Telnet dialogue plan after the remaining
read-only sample inspection. Its schema 10, RFC 854 parsing, exact byte/source
coverage, bounded query, and verification contract is recorded in
`docs/M3_SLICE2_IMPLEMENTATION.md`. That slice is now complete.

The user approved the detailed M2 slice 5 implementation plan. Its durable
contract, revalidated sample facts, and verification gates are recorded in
`docs/M2_SLICE5_IMPLEMENTATION.md`.

M2 slice 6 is complete. Its stable query schemas, bounded triage rules, exact
Telnet/HTTP-form acceptance criteria, and implementation order are recorded in
`docs/M2_SLICE6_IMPLEMENTATION.md`.

The user approved the corrected slice 6 plan after the remaining read-only
sample inspection. Implementation is authorized, but every tested sub-slice
must update this checkpoint before the next behavior slice starts.

## Completed checkpoint

- The project was moved out of the parent personal-script repository into the
  standalone `C:\Users\Administrator\OneDrive\CTF\Auto-Shark` Git repository.
- Repository rules now require durable, test-backed checkpoint updates.
- The focused inspection of all five local acceptance captures is complete and
  recorded in `docs/ACCEPTANCE_SAMPLES.md`.
- The implementation plan and milestone exit criteria are recorded under
  `docs/` rather than existing only in an Agent conversation.
- M0 created the Python 3.9+ `src/auto_shark` package, uv lockfile, CLI entry
  point, Ruff/pytest configuration, and Windows 3.11/Linux 3.9 CI matrix.
- M1 implemented versioned canonical IDs, bounded-memory hashing, the SQLite v1
  schema/migration, content-addressed atomic blob writes, bounded argument-list
  subprocess execution, structured TShark capability probing, and machine-local
  project create/open/status commands.
- M2 slice 1 implemented bounded line-streaming subprocess output, structured
  HTTP-over-TCP metadata parsing, SQLite schema 2, schema 1 upgrade, persisted
  frame/conversation/message records, and request-centered HTTP transactions.
- `auto-shark analyze` now creates a project, records the TShark capability and
  tool run, ingests HTTP metadata in one database transaction, preserves
  unmatched/orphan cases, and emits a machine-readable analysis summary.
- M2 slice 2 added SQLite schema 3, incremental hexadecimal stdout decoding,
  bounded on-demand HTTP body extraction, atomic content-addressed blob writes,
  original evidence locators, explicit body states, and `extract-body` CLI.
- M2 slice 3 added SQLite schema 4, byte-accurate ordered URL-form parsing,
  conservative Base64/Base64URL/hex recognition, bounded transform budgets,
  streaming known-flag search with chunk overlap, exact match evidence,
  candidate ranking/deduplication, and idempotent `scan` CLI.
- M2 slice 4 added SQLite schema 5, persistent body tasks, URI-scoped automatic
  request/response selection, per-body and total extraction budgets, explicit
  completed/failed/skipped states, one-time capability reuse, and the combined
  `analyze --with-bodies --scan` workflow.
- M2 slice 5A added SQLite schema 6, fixed-window file signature scanning,
  bounded artifact carving, structural PNG/JPEG/ZIP/PDF validation, conservative
  RAR/GZIP/PE recognition, explicit scan/artifact truncation states, prefix and
  trailing range evidence, artifact content deduplication, and multi-source
  artifact provenance. `scan --with-files` is explicit; ordinary `scan` keeps
  its previous cost and behavior.
- M2 slice 5B added SQLite schema 7, capability-gated streaming TCP segment
  indexing, per-run segment/skip provenance, per-direction sequence
  reconstruction, first-seen overlap policy, exact duplicate-source ranges,
  exact conflicting-byte records, explicit gaps, midstream state, bounded
  index/direction/total output budgets, and current reconstructed-stream
  evidence with frame ranges. `reconstruct-stream` exposes the workflow.

## Verification at this checkpoint

Environment paths below are local evidence, not production defaults:

- `UV_PROJECT_ENVIRONMENT=C:\Users\Administrator\AppData\Local\AutoShark\venvs\dev`
- `uv sync --all-groups`: succeeded with CPython 3.11.15.
- `uv run ruff check .`: all checks passed.
- `uv run pytest --cov=auto_shark --cov-report=term-missing`: 14 passed,
  total coverage 68 percent on Windows Python 3.11.15.
- Separate environment `...\venvs\py39`; `uv sync --python 3.9 --all-groups`
  and `uv run pytest -q`: 45 passed on CPython 3.9.25 after M2 slice 4.
- `auto-shark probe --tshark <portable 4.6.7>`: usable; HTTP, HTTP export,
  TCP reassembly, FTP, FTP-DATA export, Telnet, and multipart all available.
- A real `networking.pcap` project was created and reopened under
  `%LOCALAPPDATA%\AutoShark\projects`; it recorded SQLite schema 1, 4,570 bytes,
  and SHA-256 `7072e7e1a42efe6b77bc0a428b5297440f123098143e830c1e9b7c7ae6886165`.
- After M2 slice 1, `uv run ruff check .` passed and the Python 3.11 suite
  reported 23 passed. After M2 slice 2, the Python 3.11 suite reported 35
  passed with 67 percent total coverage; Ruff also passed.
- Real `菜刀666.pcapng` analysis under `%LOCALAPPDATA%` recorded schema 2,
  24 HTTP-over-TCP requests, 23 responses, 23 matched transactions, one
  unmatched request, and zero orphan responses.
- Exact URI `/upload/1.php` produced 19 matched transactions. Stream counts
  were `1:6, 2:3, 4:1, 5:1, 7:2, 9:3, 10:2, 13:1`; all 19 have a response.
- The completed TShark run has exit code 0 and untruncated stderr. Four UDP SSDP
  `M-SEARCH` messages also carry `http.request` fields in Wireshark, so the
  HTTP/TCP adapter deliberately uses `tcp && (http.request || http.response)`.
- Real body extraction verified schema 3 and these capture facts:
  - frame 1068 request: 204,999/204,999 bytes, complete, SHA-256
    `ab5303ab5c7f47af759a9153951c1256c82c7409b71c813ac677233c0191662d`;
  - frame 1156 response: 185,076/185,076 bytes, complete, SHA-256
    `ce19066c660bfb155945767598257fe003481969614e1650fa617cdd195d3920`;
  - frame 180 request: 100/675 bytes under a 100-byte policy limit, recorded as
    `limit-truncated` with SHA-256
    `bfb8c1508d58163d66fdfe507d2543854cf942e85b525518807f85dc2c4db3fb`;
  - frame 1367 response: 230/230 bytes, complete, SHA-256
    `6c1cbfc323dfb9bc2724c055ab0c1fad88a70b79ca058b8b697b52d422d45214`;
    its bytes begin with application delimiter `->|` and then ZIP magic, so
    carving must scan bounded offsets instead of checking offset zero only;
  - frame 645 request: no declared or extracted body, recorded as `absent`
    without creating an empty blob or evidence row.
- All four body blob sizes and hashes were independently re-read from disk and
  matched SQLite. All associated tool runs completed with exit code 0, and the
  isolated `jobs` directory was empty after extraction.
- After M2 slice 3, `uv run ruff check .` passed; Python 3.11 reported 43
  passed and 71 percent total coverage.
- A clean `菜刀666` schema 4 project ran analyze, extraction, and scan twice.
  Both scans remained exactly 3 bodies, 4 form fields, 7 transforms, and zero
  current flag candidates; database row counts stayed 4/7/0.
- Frame 1068 lineage is:
  - `aa`: URL-form value, 38 bytes;
  - `action`: URL-form value 440 bytes -> Base64 output 328 bytes, SHA-256
    `826e5936f6e0217b3241950382139d4247a2a795ffa0a08421428c353bb932b1`;
  - `z1`: URL-form value 40 bytes -> Base64 path `D:\wamp64\www\upload\6666.jpg`,
    29 bytes, SHA-256
    `a6aa2c2035ace960e44814d0f078c5b7f3b22d8d576c40fb5e7afc52c8aa86fa`;
  - `z2`: URL-form value 204,452 bytes -> hex-decoded JPEG 102,226 bytes,
    SHA-256 `a7b43078200c11f3e6eeb7ef6693db27d703460df75fd220c4e05f4a20ac50fa`.
  Large transform output has no SQLite `text_value`; bytes remain in the blob
  store. The PHP action is displayed statically and never executed.
- A clean `被嗅探的流量` project independently found exactly one candidate from
  frame 233 without access to the answer oracle. Its `flag-match` evidence is
  frame 233, body offset 164,076, length 38, parent blob SHA-256
  `42a40528f6d4ad94653f4ff0e798b41184e5c79938c5a57942ae3e0915a36073`.
- After M2 slice 4, Ruff passed; Python 3.11 reported 45 passed with 69
  percent total coverage. Workflow orchestration is additionally covered by
  the following real end-to-end runs.
- One command on a new `菜刀666` schema 5 project selected all request/response
  members for the 19 `/upload/1.php` transactions: 38 selected, 38 completed,
  0 failed, 0 skipped, 228,842 extracted bytes. Database `body_task` and
  `http_body` both report the same 38/228,842 totals; all bodies were complete,
  all tool runs completed, the jobs directory was empty, and ZIP magic in frame
  1367 was preserved at body offset 3.
- A separate 100-byte total-budget run selected the same 38 messages, completed
  1 with exactly 100 extracted bytes, and persisted 37 `skipped-budget` tasks.
  No selected message was silently omitted.
- Parent repository status after migration no longer lists `auto-shark/` and
  retains the pre-existing `.idea`, archive cache, and `pyshark/` changes.
- Before M2 slice 5 implementation, all five private sample hashes and focused
  protocol facts were rechecked read-only against TShark 4.6.7. The frame 233
  JPEG range `[138,164076)` hashes to
  `d8e9ba607bde8bccb1bf812e7d0d354abf41a57c0461e6b59c1fa9d5dcc58888`;
  the former acceptance hash was disproved by a fresh export and common range
  variants, so `docs/ACCEPTANCE_SAMPLES.md` was corrected before coding.
- The same inspection confirmed frame 1367 ZIP range `[3,227)`, a 22-byte EOCD
  comment, three trailing application bytes, and one encrypted member that must
  not be opened. It also confirmed the FTP RAR hash, seven HTTP-form capture
  retransmissions, four one-byte conflicting overlaps in target stream 2, and
  three identical 1,380-byte retransmissions in WebShell stream 0.
- After M2 slice 5A, `uv run ruff check .` passed. Python 3.11.15 reported 58
  tests passed with 71 percent total coverage; Python 3.9.25 reported the same
  58 tests passed. Tests cover schema 5-to-6 migration, idempotent duplicate
  provenance, window-boundary signatures, ZIP comments and large trailing
  regions, JPEG stuffed bytes/false EOI, PNG CRC, truncation states, and a
  128 MiB sparse input constrained to a 4 KiB scan budget.
- Real schema 6 carving of `m2-sniffed-scan.auto-shark` produced one validated
  artifact: frame 233 JPEG offset 138, length 163,938, SHA-256
  `d8e9ba607bde8bccb1bf812e7d0d354abf41a57c0461e6b59c1fa9d5dcc58888`,
  prefix length 138, and trailing range offset 164,076 length 85.
- Real schema 6 carving of `m2-caidao-workflow.auto-shark` scanned 133 eligible
  body/transform evidence records and produced two validated artifacts:
  frame 1068 transform-output JPEG offset 0, length 102,226, SHA-256
  `a7b43078200c11f3e6eeb7ef6693db27d703460df75fd220c4e05f4a20ac50fa`;
  and frame 1367 ZIP offset 3, length 224, SHA-256
  `7484bdeddf429bfa7da36da7d522115d7156c46f4280cc2f45dcdf679f640c20`,
  with three-byte prefix and trailing ranges.
- Repeated real carving reported zero new artifacts and stable counts. The
  multipart project remained 1/1/1/1 for file_scan/file_carve/artifact/link;
  the WebShell project remained 133/2/2/2. Both databases pass
  `PRAGMA foreign_key_check`; both runtime `jobs` directories remain empty.
- After M2 slice 5B, `uv run ruff check .` passed. Python 3.11.15 reported 67
  tests passed with 75 percent total coverage; Python 3.9.25 reported the same
  67 tests passed. Tests cover schema 6-to-7 migration, dynamic optional
  TShark fields, bidirectional isolation, exact retransmissions, partial and
  conflicting overlaps, gaps, midstream captures, index/segment/direction/total
  budgets, per-segment skip records, rerun isolation, current evidence
  selection, stable reconstruction rows, and empty temporary job cleanup.
- A clean real Telnet stream 0 project indexed 36 segments/310 payload bytes.
  Client-to-server reconstructed 124 bytes (frames 4-52), SHA-256
  `7bf3a3d8c8d8664c12f6c527e809b10a4b76ce28a778f20ca5dff5eae1f6b700`;
  server-to-client reconstructed 186 bytes (frames 6-55), SHA-256
  `420bcf53bf0f7cf10f9795d4c2b053543b5aacc23280cdeeba40b3067c0656cb`.
  Both directions are complete, gap-free, conflict-free, and not midstream.
- A clean real HTTP-form stream 2 project indexed 26 segments/9,659 payload
  bytes. Server-to-client removed two exact 20-byte retransmissions and emitted
  7,548 bytes, SHA-256
  `41823c9d6a1302bcb4bfa27e6d9ff72e305b4fee605c3367fd8a4dd5b5f5e5cc`.
  Client-to-server emitted the deterministic first-seen 2,067 bytes, SHA-256
  `d4334f464d6f57df87d031b35108ecd99d654875749d63760ff1cc0a61229d54`,
  and persisted four one-byte conflicts at relative sequence 2,067 against
  first frame 64 from conflicting frames 184, 291, 308, and 326.
- A clean real WebShell stream 0 project indexed 289 segments/585,557 payload
  bytes. Three exact 1,380-byte retransmissions were retained as duplicate
  provenance but omitted from output. The complete 581,417-byte stream hashes
  to `5e5b2b9cd1854e1435bc02b5f6ec5c836346e41d10346aed52d27383e75e71eb`.
- Repeating all three real reconstructions preserved segment, reconstruction,
  source, gap, conflict, evidence, and output hashes; only new tool-run and
  segment-run provenance was appended. Every output hash was independently
  re-read from disk, every database passed `PRAGMA foreign_key_check`, every
  TShark run completed with untruncated stderr, and every `jobs` directory was
  empty.
- A separate real WebShell stream 0 run with a 100-byte index budget persisted
  all 289 payload segments as `payload-budget` skips, produced no fake blob,
  returned a `truncated` direction, and left no selected segment silent.
- The final slice 6 read-only sample inspection reverified all five capture
  hashes with TShark 4.6.7 without reading the adjacent answer file. Telnet
  client stream 0 contains its frame 41 known-format value at reconstructed
  output range `[82,120)`, length 38, with frame 41 as the sole primary source;
  that slice hashes to
  `a39095fe3a3f543d2e09d29fe191296700e3d6e0a64dfce52e101529ca78747b`.
- HTTP request frame 20 pairs to response frame 26 through TShark's explicit
  request reference. Its URL-form body is 65 bytes, SHA-256
  `00a5ef097b7f875957d0145aa414bd976ebc8e7c33145200755eafe5b658117c`,
  with ordered raw value ranges `email [6,10)`, `password [20,52)`, and
  `captcha [61,65)`. The password is a 32-byte printable hexadecimal-shaped
  value. Both inspected runtime databases pass foreign-key checks and have
  empty `jobs` directories.
- M2 slice 6 query sub-slice is implemented and focused verification passed:
  `uv run ruff check .` succeeded and
  `uv run pytest -q tests/test_queries.py tests/test_database.py` reported
  8 passed. Coverage includes schema 7-to-8 migration, bounded pagination,
  exact URI filtering, primary-source frame ranges, recorded frame-range audit
  fields, and explicit stream conflict output.
- Repeated real query calls returned byte-identical JSON. The 19 WebShell
  `/upload/1.php` transactions use `auto-shark.transactions/v1` and hash to
  `a5193dd4ee0a73a196f8370d80ac597a798b6843da7e5625bffe096eddac2385`;
  the two Telnet directions use `auto-shark.streams/v1` and hash to
  `779041d2ac31af1db743e5c19da76e34fe809206e7b843918bb97f562e73f4d7`.
  The HTTP-form stream query exposes statuses `complete,conflicting` and four
  conflicts. These real runtime projects were migrated to schema 8 by the
  query command; captured blobs were not changed.
- M2 slice 6 triage code and focused synthetic verification are implemented.
  The 21-test search/triage/query/database/CLI group passes and covers current
  evidence selection, historical TCP exclusion, TCP output-to-frame mapping,
  artifact-local coordinates, form role ranking, placeholders, policy-keyed
  idempotency, per-input/total/evidence/candidate budgets, explicit failures,
  CLI limit forwarding, orphan transactions, and empty pages.
- Windows Python 3.11.15 full regression passes: `uv run ruff check .` and
  `uv run pytest --cov=auto_shark --cov-report=term-missing` reported 81 tests
  passed with 81 percent total coverage.
- The separate CPython 3.9.25 uv environment also passes all 81 tests. Both
  supported core runtimes are green before any real schema 8 triage run.
- Clean schema 8 Telnet acceptance passed in
  `m2-slice6-telnet.auto-shark`. Reconstruction retained the verified 36
  segments/310 payload bytes and both schema 7 output hashes. Two identical
  triage runs selected/scanned two current directions and produced exactly one
  candidate at rank 100. Its exact evidence is reconstructed range `[82,120)`,
  length 38, frame 41-to-41, with `contributing_frames: [41]`. Stable row
  counts are triage_scan/candidate/link/signal `2/1/1/1`; all 30 blobs rehash,
  foreign-key violations are zero, and `jobs` is empty.
- Clean schema 8 HTTP-form acceptance passed in
  `m2-slice6-http-form.auto-shark`. Request frame 20 pairs to response 26; its
  complete 65-byte body retains SHA-256
  `00a5ef097b7f875957d0145aa414bd976ebc8e7c33145200755eafe5b658117c`.
  Stream 2 exposes `complete,conflicting` directions and all four conflicts.
  Seven current evidence inputs were scanned twice with stable results and no
  known-format match. Ordered fields retain raw ranges `email [6,10)`,
  `password [20,52)`, and `captcha [61,65)` plus all three URL transform links.
  Password ranks 80 as `sensitive-field`; email/captcha rank 13 as context.
  Stable row counts are `7/3/3/12`; all 28 blobs rehash, foreign-key violations
  are zero, and `jobs` is empty.
- Repeated schema 8 multipart regression selected two current inputs
  (`http-body` and `file-carve`), scanned 328,099 bytes without limits/failures,
  and retained exactly one known-format candidate. Its evidence remains frame
  233, parent-body offset 164,076, length 38, over parent SHA-256
  `42a40528f6d4ad94653f4ff0e798b41184e5c79938c5a57942ae3e0915a36073`;
  the artifact blob was scanned in artifact-local coordinates and did not
  duplicate or shift the match.
- Repeated schema 8 WebShell regression selected/scanned all 135 current inputs:
  38 HTTP bodies, 95 transform outputs, and two complete file carves, totaling
  659,117 bytes. It produced zero candidates with no truncation, budget skip,
  candidate limit, or failure. Multipart and WebShell results were identical
  across repeat calls; all 2/46 blobs respectively rehash, both databases have
  zero foreign-key violations, and both `jobs` directories are empty.
- Every M2 roadmap exit item is now implemented and evidenced: streaming HTTP
  metadata, precise pairing, bounded body/TCP reconstruction, bounded transform
  search, stable queries, and explainable/idempotent candidate ranking. M2 is
  complete; generic unstructured-token heuristics remain intentionally in M4.
- Final verification after the query aggregation assertions remained green:
  Ruff passed; Windows CPython 3.11.15 reported 81 tests and 81 percent total
  coverage; CPython 3.9.25 reported the same 81 tests passed. All four schema 8
  runtime databases above return `PRAGMA integrity_check=ok`, zero foreign-key
  violations, and empty `jobs` directories. `uv build` produced the sdist and
  wheel, and the wheel contains `queries.py`, `search.py`, and `triage.py`.
- M3 FTP read-only inspection verified one control/data transfer in the FTP
  acceptance capture: PASV 42/44, `RETR flag.rar` frame 49, `150` frame 51,
  FTP-DATA frame 55, and `226` frame 66. Frame 55 explicitly references setup
  frame 44 and command frame 49, carries 164 payload bytes on TCP stream 4,
  starts with RAR4 magic, and hashes to
  `941702f949e60d081210d33a98552b32d3e5b36673be2e6c0f439904f46b5597`.
  TShark marks no retransmission or out-of-order condition. No answer file or
  transferred-content member was read.
- M3 FTP metadata sub-slice is implemented at schema 9. Ruff and the 18-test
  FTP protocol/metadata/migration/capability group pass. Tests cover IPv4/IPv6,
  exact field/frame parsing, multi-frame transfer grouping, stable reruns,
  explicit unresolved records, message limits/skips, capability failure, and
  cross-platform filename sanitization.
- Clean real `m3-ftp-metadata.auto-shark` indexing ran twice with identical
  summaries: 6 messages (2 requests, 3 responses, 1 FTP-DATA), one transfer,
  and zero skips/unresolved cases. Stable business rows remain 6 protocol
  messages, 5 FTP control rows, 1 data row, 1 transfer, and 1 transfer-message
  link; two tool runs retain 12 message-run provenance links. The transfer maps
  setup/command/data frames 44/49/55, TCP stream 4, the exact server-to-client
  direction, and sanitized `flag.rar`. Integrity is `ok`, foreign keys report
  zero violations, and `jobs` is empty. No artifact exists yet.
- M3 FTP export orchestration and focused tests are implemented. The full
  Windows Python 3.11 suite currently reports 95 tests passed at 83 percent
  coverage. FTP-focused tests cover exact structured parsing, schema 8-to-9,
  multi-frame grouping, explicit unresolved and message-limit states, complete
  reconstruction coverage, partial rejection, pre-reconstruction output
  budgets, RAR4 magic-only classification, artifact/evidence idempotency, and
  CLI limit forwarding.
- Repeated real `index-ftp` on `m3-ftp-metadata.auto-shark` returned identical
  `auto-shark.ftp-index/v1` summaries and one complete 164-byte artifact. The
  exact `ftp-data` evidence is frame 55, `[0,164)`, direction
  `172.16.66.10:14438>172.16.66.188:51801`, over the same single reconstruction
  blob SHA-256
  `941702f949e60d081210d33a98552b32d3e5b36673be2e6c0f439904f46b5597`.
  Frames 44/49/55, stream 4, complete/no-gap/no-conflict state, RAR4 magic,
  `flag.rar`, and `unreviewed` artifact state are linked. Stable business rows
  are one transfer/message/reconstruction/segment/artifact, two evidence rows,
  and one blob; all six accumulated TShark runs completed with exit 0 and
  untruncated stderr. Blob rehash, integrity, foreign keys, and empty jobs pass.
- A separate real 100-byte transfer budget project persisted one
  `skipped-budget` transfer before TCP reconstruction. It has one metadata tool
  run and zero TCP segments, reconstructions, blobs, evidence, or artifacts;
  integrity, foreign keys, and empty jobs pass.
- Final M3 FTP verification passes Ruff; Windows CPython 3.11.15 reports 97
  tests at 83 percent total coverage; CPython 3.9.25 reports the same 97 tests
  passed. A final real rerun after unresolved-group and reconstruction-failure
  hardening remained one complete transfer/artifact at 164 bytes. Both schema 9
  runtime projects pass integrity, foreign keys, and empty jobs. The built
  package includes `ftp.py` and `protocols/ftp.py`.
- M3 Telnet schema 10 and the standalone incremental RFC 854 parser are now
  implemented as the first tested sub-slice. The parser treats current TCP
  reconstruction bytes as authoritative, preserves absolute ranges across
  arbitrary chunks, and covers negotiation, subnegotiation, escaped IAC,
  incomplete controls, CR-NUL, binary bytes, and the sample's split `IAC DM`
  shape. `uv run pytest -q tests/test_telnet_protocol.py tests/test_database.py`
  reports 14 passed; focused Ruff checks pass. Persistence and CLI behavior are
  not implemented yet.
- M3 Telnet persistence and TCP role evidence are now implemented in the
  focused synthetic sub-slice. TCP summaries expose the initial non-ACK SYN
  initiator/responder when `tcp.flags.ack` is available; no port fallback is
  used. Telnet discovery, current reconstruction reuse, exact record/source
  coverage, prompt/input and exact echo relations, split-IAC handling, stable
  reruns, record-budget skips, and blob reuse pass 24 focused tests. Ruff passes
  for the touched modules. Stable query and CLI surfaces are the next sub-slice.
- M3 Telnet indexing, bounded dialogue query, and both CLI surfaces are now
  implemented. Candidate references are dynamic same-capture/direction/blob
  range overlaps; previews are escaped and separately budgeted; metadata and
  parse skips are explicit. Full Windows Python 3.11 verification passes Ruff
  and 114 tests at 85 percent total coverage (Telnet persistence 87 percent,
  protocol parser 97 percent). Real fresh-project acceptance and Python 3.9
  validation remain pending.
- M3 Telnet slice 2 is complete at schema 10. Final Windows CPython 3.11.15
  verification passes Ruff and 119 tests at 85 percent total coverage; Telnet
  persistence is 91 percent, its protocol parser 97 percent, and queries 98
  percent. CPython 3.9.25 passes the same 119 tests. `uv build` succeeds and the
  wheel contains `telnet.py`, `protocols/telnet.py`, and `queries.py`.
- Clean real `m3-telnet-dialogue-clean.auto-shark` indexing is stable across
  repeated current runs: one complete dialogue, 36 metadata frames, 44 records,
  310 parsed bytes, zero skips, 54 record-source mappings, and three relations.
  The client direction is the verified complete 124-byte blob
  `7bf3a3d8c8d8664c12f6c527e809b10a4b76ce28a778f20ca5dff5eae1f6b700`;
  the server direction is the verified complete 186-byte blob
  `420bcf53bf0f7cf10f9795d4c2b053543b5aacc23280cdeeba40b3067c0656cb`.
- Real Telnet records cover client `[0,124)` and server `[0,186)` exactly with
  no gap or overlap. Login prompt `[71,107)` frame 22 links to client input
  `[76,82)` frames 24/27/30/33/36 and its exact server echo. Password prompt
  `[113,123)` frame 39 links to client `[82,122)` frames 41/43. The existing
  rank-100 candidate remains exact `[82,120)`, frame 41 only, and is linked
  dynamically without rescoring.
- The real split `IAC DM` is one command record at server `[182,184)`, command
  242, with source mappings frame 53 `[182,183)` and frame 54 `[183,184)`.
  Bounded query output reports `current=true`, all 44 records, reversible
  preview `\\xff\\xf2`, and exactly 310 total preview bytes.
- Clean real `m3-telnet-budget-clean.auto-shark` with `--max-records 1`
  persists one truncated dialogue/run, one 3-byte record, and two exact
  `record-limit` skips totaling 307 bytes. Parsed plus skipped bytes equal the
  full 310-byte bidirectional input; no selected direction disappears.
- Both final schema 10 runtime projects pass SQLite integrity and foreign-key
  checks, all blobs independently rehash and match length, and both `jobs`
  directories are empty. The complete project's stable business rows are one
  dialogue, 44 records, 54 source mappings, three relations, zero skips, and
  one candidate. No answer file or captured artifact was opened, listed,
  unpacked, rendered, decrypted, or executed.

## Active decisions

- Stable IDs are SHA-256 digests of versioned canonical JSON locators.
- SQLite stores indexes and lineage; large bytes use a content-addressed blob
  directory within each machine-local analysis project.
- TShark support is decided by field/protocol capability probes. Version is
  provenance, not the only compatibility gate.
- Public JSON schemas use an explicit `schema_version` and reject unknown major
  versions.
- Python 3.9 compatibility takes precedence over Ruff's `UP045` suggestion;
  `Optional[...]` remains intentional because `X | None` syntax needs 3.10.
- `ctf-stego-toolkit` integration requires JSON output and an explicit output
  directory; terminal prose is never parsed as a result contract.
- HTTP transaction IDs are request-frame based. Pairing uses both TShark
  association directions and preserves extra responses, unmatched requests,
  and orphan responses; stream ordering is never used to guess a response.
- HTTP body status distinguishes complete, empty, absent, missing, partial,
  policy-truncated, and length-mismatch. Only nonempty bytes create blobs and
  evidence. A later full extraction can upgrade a blob's completeness.
- On Windows, `tempfile.mkstemp` descriptors are wrapped with `os.fdopen`;
  generic `open(fd, ...)` produced `EINVAL` and is covered by the real smoke run.
- Only complete URL-form bodies receive structured field transforms. Truncated
  bodies remain searchable raw evidence but are not parsed as complete forms.
- High-confidence known-format search recognizes explicit `flag`, `ctf`, `key`,
  and `answer` prefixes. Structured authentication-field triage is a separate
  detector so preceding printable bytes are not swallowed into a false value;
  generic unstructured token heuristics remain M4 scope.
- Candidate links point to `flag-match` evidence with exact byte offset/length,
  which in turn references the parent evidence/blob; they do not merely point
  at the whole body.
- Both URL-form decoding and second-layer Base64/hex output count against the
  configured per-output and total transform byte budgets. Over-budget raw field
  slices remain evidence, but no decoded blob or transform is created.
- Automatic body selection follows persisted transaction membership rather
  than guessing stream order. Detailed per-body results live in SQLite; CLI
  workflow JSON returns counts by default and includes paths/details only with
  `--verbose-bodies`.

## Risks and constraints

- The local `ctf-stego-toolkit` currently lacks the required JSON/output-dir
  contract. That cross-project change needs its own explicit implementation
  checkpoint before remote integration.
- Linux Python 3.9 validation requires the verified remote node or CI runner;
  current local development validates Windows Python 3.11.
- PyCharm was not found in the standard install/registry locations. It is not a
  build prerequisite and no installation is planned automatically.

## Next executable step

Plan and contract the next M3 slice before implementation: bounded protocol and
conversation summary plus a persistent manual-analysis queue. Reuse current
HTTP/TCP/FTP/Telnet/file records, distinguish unavailable/partial analyzers,
and do not duplicate payload bytes or collapse evidence-specific review state.
