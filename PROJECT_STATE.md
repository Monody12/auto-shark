# Auto-Shark Project State

Updated: 2026-08-17, Asia/Shanghai

This is the canonical resume checkpoint. Update it after every tested slice.

## Objective

Deliver the v1 offline CTF packet-analysis workbench defined in `AGENTS.md` and
`docs/ARCHITECTURE.md`, with a Python 3.9+ CLI core, Windows/Python 3.11 GUI,
TShark structured parsing, bounded on-disk evidence processing, explainable
candidate ranking, static file analysis, and constrained optional Linux jobs.

## Current milestone

v1 shipped at 0.1.0. M0 through M8 exit criteria are complete.

Status: all milestones complete. Two user-executable residuals remain
recorded in `docs/RELEASE_CHECKLIST.md`: the one-time hands-on clean-machine
install test and live Linux-node `remote-probe`/`remote-run` validation
(needs user-held node credentials). Neither blocks the published v1.

The first M3 slice is active. Its FTP structured metadata, explicit frame
correlation, bounded TCP reuse, static export, and no-unpack contract is
recorded in `docs/M3_SLICE1_IMPLEMENTATION.md`. That slice is now complete.

The user approved the M3 directional Telnet dialogue plan after the remaining
read-only sample inspection. Its schema 10, RFC 854 parsing, exact byte/source
coverage, bounded query, and verification contract is recorded in
`docs/M3_SLICE2_IMPLEMENTATION.md`. That slice is now complete.

The user approved the remaining M3 protocol/conversation summary, multipart
finding, and persistent manual-analysis queue scope. Its schema 11, status
vocabulary, bounded CLI, queue preservation rules, and five-sample acceptance
contract are recorded in `docs/M3_SLICE3_IMPLEMENTATION.md`.

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
- M3 slice 3A implements schema 11 and bounded payload-free TShark capture
  inventory. Stable protocol observations and TCP/UDP conversation profiles
  retain per-run provenance, explicit frame/label/conversation skips, IPv4 and
  IPv6 endpoints, byte/frame totals, and initial-SYN TCP roles without guessing
  UDP roles. Coverage uses distinct complete, partial, not-run, unavailable,
  failed, and budget-limited states and prefers current analyzer results over
  protocol labels. Ruff and the full Python 3.11 suite pass with 128 tests.
- Two real `index-summary` runs against the clean Telnet schema 11 project each
  processed 59 frames and produced five protocol observations, one TCP stream
  profile, and 310 payload bytes. The SYN-proven endpoints are
  `192.168.221.128:1146` to `192.168.221.164:23`; Telnet coverage remains
  complete from the current 44-record parser result. Stable profile counts did
  not grow, while two inventory/run links preserve provenance. SQLite
  integrity, foreign keys, and the empty jobs directory pass.
- M3 slice 3B implements header-only multipart metadata, conservative unique
  part-to-carve correlation, declared/detected type mismatch findings, and a
  bounded static success-semantic scan limited to complete nontruncated HTTP
  5xx response bodies. Synthetic tests cover multi-part ambiguity, unique
  mismatch, exact result ranges, incomplete-body skipping, and idempotent
  business rows. Focused Ruff and 13 tests pass.
- The existing multipart project was migrated to schema 11 and frame 260 was
  extracted through the bounded HTTP body workflow: 764 complete bytes,
  SHA-256 `4793d6d43b282bd3215d16f85a8dba8f147ce583478f8c901aae154d6fa7bdea`.
  Two repeated header-only multipart/finding runs keep two stable parts: frame
  233 `upfile` / `flag.jpg` / `image/jpeg` uniquely matches the current JPEG
  carve, while frame 54 remains explicitly unresolved because it has no carve.
  Frame 260 HTTP 500 creates one stable contradiction finding with exact body
  range `[634,648)` and text `upload success`; the second run only adds
  finding-run provenance. All three project blobs rehash, integrity and foreign
  keys pass, and jobs remains empty. No artifact was opened or rendered.
- M3 slice 3C implements schema 11 queue contracts plus schema 12 append-only
  repair for projects materialized during the earlier 3A checkpoint. Stable
  manual tasks deduplicate multiple signals by capture subject, rebuilds replace
  only automatic signals and evidence links, and manual state, review marks,
  notes, and artifact review state are preserved. The initial rank rules cover
  rank-100 candidates, analyzer/HTTP contradictions, TCP conflict or partial
  results, unreviewed RAR/ZIP/executable artifacts, trailing/unmatched/orphan
  HTTP, and bounded unsupported protocols. Summary, manual-queue, and
  manual-task CLI queries support independent pagination/filter/budget limits.
- Final Windows CPython 3.11 verification passes Ruff and 137 tests at 86
  percent total coverage; CPython 3.9 passes the same 137 tests. `uv build`
  succeeds and the wheel contains `inventory.py`, `protocols/inventory.py`,
  `protocols/multipart.py`, `findings.py`, `manual_queue.py`, and `queries.py`.
- All five clean acceptance runtime projects ran the complete
  inventory -> multipart/findings -> manual queue workflow twice. Stable
  current rows are: Telnet 59 frames/one TCP profile/310 payload bytes/one
  rank-100 task; HTTP form 356 frames/36 profiles/15 tasks; FTP 301 frames/90
  profiles/one unreviewed RAR represented in eight queue signals; multipart
  335 frames/22 profiles/two parts/one contradiction finding/14 tasks; and
  WebShell 2,139 frames/18 profiles/eight tasks. The second run adds only
  inventory, finding-run, and queue-run provenance; current summary counts stay
  stable. Four projects rehash every Blob successfully. The WebShell runtime
  retains one pre-existing Windows-unopenable historical Blob path in its
  database; it is recorded as residual machine-local risk and was not changed.
- M4 checkpoint 4A adds schema 13 detector-run/skip provenance and bounded
  unknown flag-like candidate scanning. Unknown printable brace tokens rank 78;
  mixed-class long tokens rank 45 and do not enter the manual queue. Known
  prefixes, binary brace data, URLs, ordinary assignments, and Base64-looking
  values are excluded. Exact candidate evidence, chunk-boundary overlap,
  per-input/total/result budgets, rerun stability, and queue state preservation
  are covered by new tests.
- M4 4A verification passes Ruff and the full Windows CPython 3.11 suite:
  142 tests at 86 percent coverage. CPython 3.9.25 passes all 142 tests. Five
  clean acceptance projects each ran `detect` twice. Telnet, FTP, multipart,
  and HTTP-form completed with zero new unknown candidates; existing Telnet and
  multipart rank-100 candidates and HTTP password rank 80 remain unchanged.
  WebShell has zero new candidates but remains `partial` because of its
  pre-existing Windows-unopenable historical Blob path. All five databases pass
  integrity and foreign-key checks; generated detector runs retain provenance.
- M4 checkpoint 4B adds bounded HTTP query and complete URL-form parameter
  inspection, byte-accurate raw query evidence, multi-signal SQL-injection
  classification, nearest clean-request comparisons, response status/length
  evidence, explicit partial confidence caps, stable per-request events,
  semantic duplicate links, endpoint/parameter findings, and manual-queue
  refresh. Parameter, event, finding, preview, and response-completeness limits
  are covered, including reruns over existing findings and failed tool-run
  provenance.
- Final 4B verification passes Ruff. Windows CPython 3.11.15 reports 154 tests
  at 87 percent total coverage; CPython 3.9.25 passes the same 154 tests. Each
  of the five local acceptance projects ran the integrated detector twice with
  zero SQL events or findings. Existing Telnet/multipart rank-100 candidates,
  the HTTP-form rank-80 candidate, and Telnet's `in-progress` manual state are
  unchanged. Four projects rehash every Blob; the WebShell project retains its
  one previously recorded missing historical Blob, reports `partial`, and all
  five databases pass integrity, foreign keys, and empty-jobs checks.
- The machine-local public `markofu/workshop` SQLi teaching capture ran twice
  with one stable partial event and one finding: request frame 8, response frame
  10, target `GET /sql2.php#q2`, signal `boolean-expression`, and exact raw URI
  range `[22,52)`. It has no clean comparison request, so confidence remains
  0.68 and status remains `partial`. One open finding-review task is stable;
  integrity, foreign keys, completed detector tool runs, and empty jobs pass.
- M4 checkpoint 4C adds a bounded static PHP WebShell classifier over already
  persisted complete transforms. It records one operation per selected POST,
  request/response/evidence links, normalized targets, semantic duplicate
  groups, payload metadata without payload bytes, and explicit partial,
  budget-limited, and failed provenance. The `timeline` and `findings` JSON
  queries independently cap pages, detail bytes, signals, and evidence links.
- Final M4 verification passes Ruff. Windows CPython 3.11.15 reports 160 tests
  at 86 percent total coverage; CPython 3.9.25 passes the same 160 tests.
  `uv build` succeeds and the wheel contains `detectors.py`,
  `sql_detection.py`, `webshell_detection.py`, and `m4_queries.py`.
- The existing WebShell acceptance project still returns 19 ordered events,
  eight default semantic groups, and one `static-webshell-activity` finding.
  Event kinds remain one system-information, fifteen directory-listing, one
  file-write, and two file-read operations. Frames 1068/1144 map the write to
  `D:\wamp64\www\upload\6666.jpg`; frames 1364/1367 and 1721/1724 map reads
  of `hello.zip` and `1.php`. Query output contains no inline Blob bytes.
- M4 is complete: all three detector checkpoints, the five private acceptance
  captures, the machine-local public SQL sample, stable bounded CLI schemas,
  manual-state preservation, integrity/foreign-key/jobs checks, both supported
  Python versions, and package-content checks are evidenced. Two missing paths
  in the historical WebShell runtime Blob store are a machine-local residual
  risk recorded in `PROJECT_HANDOFF.local.md`; neither is required by the
  stable 19-event/eight-group detector result.
- M5 checkpoint 5A is implemented under `docs/M5_IMPLEMENTATION.md`. Schema 14
  adds capture-scoped `investigation_note` rows while preserving legacy notes;
  first access assigns deterministic public IDs without deleting old rows.
  Human review marks validate current-capture candidates, findings, artifacts,
  behavior events, manual tasks, or evidence before upsert. Note create/update
  and bounded query commands enforce UTF-8 byte limits and stable pagination.
- Focused 5A Ruff validation passes. The schema migration, investigation API,
  CLI, and manual-queue preservation group reports 28 tests passed. Coverage
  includes legacy note migration, invalid/cross-project subjects, mark upsert,
  note update/filter/truncation, UTF-8 limits, and CLI limit forwarding.
- M5 checkpoint 5B adds the bounded `auto-shark.report/v1` read model and
  `report` CLI. It combines public capture identity, coverage, protocols,
  conversations, candidates, findings, WebShell events, artifacts, queue
  tasks, human marks/notes, evidence locators, and sanitized tool provenance.
  Reports exclude absolute project/capture paths, SQLite keys, command lines,
  stderr, Blob paths, and inline Blob/text bytes. Every collection has its own
  count/limit/truncation fields; detail and note UTF-8 budgets are independent.
- Focused 5B Ruff validation passes and the reporting/5A/database/CLI group
  reports 31 tests passed. Real `m3-telnet-dialogue-clean.auto-shark` reports
  39,874 bytes with SHA-256
  `df12d35abfd5520883da7ecd4922adb433f58b1e38755183e56c60d20cbf4db7` and
  repeated in-memory output is identical. Real `m2-caidao-workflow.auto-shark`
  reports 198,231 bytes with SHA-256
  `1e9f34f9fcfa613f0c6e17c2dfe876dd1ecaf595ef2eb3e6b7eec3ac80404dd8` and is
  likewise stable (8 deduplicated events, 1 finding, 2 artifacts).
- M5 checkpoint 5C adds the staged offline bundle exporter: a script-free
  self-contained HTML shell with escaped embedded report JSON, atomic
  publication into a new or empty destination, `report.json`/`report.html`/
  `manifest.json` with byte lengths and SHA-256 hashes, and optional bounded
  evidence ranges copied from validated Blob paths under independent item,
  per-item, and total byte limits with explicit `blob-missing`,
  `blob-incomplete`, `blob-path-escapes-project`, `range-out-of-bounds`, and
  budget skip reasons. Exported evidence is inert; nothing is rendered,
  unpacked, decrypted, or executed.
- Final M5 verification passes Ruff; Windows CPython 3.11.15 reports 170 tests
  at 87 percent total coverage; CPython 3.9.25 passes the same 170 tests.
  `uv build` succeeds and the wheel contains `investigation.py`,
  `reporting.py`, and `exporting.py`.
- All five acceptance projects passed the real report/export gate. Repeated
  `report` output is byte-identical and two fresh-directory exports are
  byte-identical per project: Telnet 41,051-byte report/31 evidence items/710
  bytes; HTTP-form 76,036/9/7,709 with one explicit `blob-incomplete` skip;
  FTP 105,950/2/328; multipart 60,107/7/329,138; WebShell 203,849/190/874,687
  with four explicit `blob-missing` skips from its recorded historical Blob
  loss. No report contains an absolute path, `.sqlite` reference, or Blob
  path. All five databases report `integrity_check=ok`, zero foreign-key
  violations, and empty `jobs` directories.
- M5 is complete: investigation state, deterministic JSON reporting, offline
  HTML/evidence export, and reopen/export determinism are all evidenced.
- M6 checkpoint 6A adds the Qt-free `gui` service facade, availability probe,
  lazy `auto-shark gui` CLI entry with an actionable install hint, and the
  ordered bounded analysis-stage builder (analyze, scan, triage, detect,
  inventory). Services wrap the existing query/mutation/export surfaces and
  return their parsed bounded JSON payloads; importing `auto_shark.cli` is
  verified by subprocess test to pull neither PySide6 nor widget modules.
- M6 checkpoint 6B adds the PySide6 main window, stage/single-run QThread
  workers with per-stage summary signals, and nine bounded pages (overview
  metrics plus report JSON, HTTP transactions with URI filter and pagination,
  streams, Telnet dialogues, candidates/findings with signal/evidence detail
  JSON, WebShell timeline, manual queue with state changes, notes with
  review-mark workflow, and bundle export). Pages render explicit no-project,
  empty, error, and `showing X of Y` truncation states. Widget tests run
  offscreen and skip without the gui extra; worker stage/failure/cancel
  behavior is covered with stubbed stages.
- Final M6 verification passes Ruff; Windows CPython 3.11.15 reports 183
  tests at 85 percent total coverage with the gui extra installed; CPython
  3.9.25 reports 176 passed plus one expected widget-test skip. `uv build`
  succeeds and the wheel contains all five `auto_shark/gui/` modules.
- The real-sample smoke opened all five acceptance projects offscreen and
  rendered every page without an error banner. Per-page row counts match the
  recorded database facts: Telnet 1 candidate/1 queue task/1 dialogue;
  HTTP-form 15 transactions/3 candidates/15 tasks; WebShell 24 transactions/
  1 finding/8 deduplicated timeline events. GUI bundle exports equal the M5
  CLI exports (31/9+1 skip/2/7/190+4 skips). The Telnet project completed a
  real scan -> triage -> detect -> inventory refresh through the stage worker
  with TShark 4.6.7. Interactive desktop acceptance remains M8 scope.
- M6 is complete: the CLI stays PySide6-free on 3.9, and the GUI reuses only
  the bounded, tested read models.
- M7 checkpoint 7A adds schema 15 (plugin manifest registry plus
  plugin_run_detail/plugin_output/plugin_output_skip) and the declared
  external-analyzer runner. `auto-shark.plugin/v1` manifests validate name,
  version, executable, capabilities, `{input}`/`{output_dir}`-only argument
  placeholders, and bounded timeout/stdout/stderr/output-file/output-byte
  limits; `plugin-probe` validates without executing. `plugin-run` verifies
  the artifact Blob hash before copying it into an isolated
  `jobs/plugins/<run-id>/input` directory, executes the analyzer through the
  bounded argument-list runner, and records every output file by path, byte
  length, and SHA-256 with explicit file/byte/total/result skip reasons.
  Auto-Shark never executes captured content itself.
- Final 7A verification passes Ruff; Windows CPython 3.11.15 reports 192
  tests at 85 percent total coverage (`plugins.py` 90 percent); CPython
  3.9.25 reports 185 passed plus the expected widget skip. `uv build`
  succeeds and the wheel contains `plugins.py`.
- The real smoke registered a `jpeg-report` manifest and ran it against the
  multipart project's frame-233 JPEG artifact
  `f387c42364a072c5a0130c81585a9e3654ff4e5fb31c6231b5c413cddecdda14`. The
  run completed with input SHA-256
  `d8e9ba607bde8bccb1bf812e7d0d354abf41a57c0461e6b59c1fa9d5dcc58888`
  (matching the verified M2 carve), one 272-byte hashed `result.json`
  confirming JPEG magic/EOI, zero skips, and an independent re-read of every
  produced file matching the recorded hashes. The project database passes
  integrity and foreign-key checks. Machine-local smoke files live under
  `%LOCALAPPDATA%\AutoShark\m7-smoke`.
- M7 checkpoint 7B adds the constrained SSH/SFTP remote runner. A
  `RemoteTransport` interface backs both the production `SshTransport`
  (argument-list ssh/sftp invocation, BatchMode, declared connect timeout,
  charset-validated host/paths/tokens so no remote shell metacharacter can
  pass) and an injectable fake for tests. `remote-probe` reports
  `test -x` availability for absolute remote executables without `PATH`
  lookup; `remote-run` reuses `auto-shark.plugin/v1` manifests whose
  executable must be an absolute POSIX path and whose substituted argument
  tokens must be shell-safe, hash-verifies the artifact Blob, stages the job
  spec with `request.json`/`request_sha256`, uploads into
  `jobs/remote/<job-id>/`, fetches the declared result JSON plus any
  `output_files` it declares, records every fetched file hash, persists
  plugin_run/detail/output/skip rows plus the schema 1 `remote_job` row with
  request/result SHA-256, and reports completed/failed/timeout with explicit
  fetch/limit/invalid-result skips.
- Final 7B verification passes Ruff; Windows CPython 3.11.15 reports 198
  tests at 85 percent total coverage (`remote.py` 85 percent, `plugins.py`
  90 percent); CPython 3.9.25 reports 191 passed plus the expected widget
  skip. `uv build` succeeds and the wheel contains `remote.py`. Local
  ssh/sftp clients were capability-detected on the Windows controller (Git
  OpenSSH). Fake-transport tests cover command construction, request/result
  hash round trips, failure/timeout/missing-result statuses, unsafe-manifest
  rejection, and sftp batch quoting; real Linux-node execution remains
  pending user-provided node credentials and is recorded as residual risk.
- M7 checkpoint 7C adds the shipped working-directory adapter
  (`auto_shark/assets/cwd_adapter.py`). It runs any declared tool with the
  job's isolated output directory as working directory, preserves the tool's
  terminal output verbatim as hashed `stdout.txt`/`stderr.txt` evidence
  files, propagates the inner exit code (124 on inner timeout), and never
  parses terminal prose into structured conclusions. Template manifests and
  usage live in `plugins/examples/README.md`.
- Real 7C smoke: the local `ctf-stego-toolkit` ran unmodified through the
  adapter against the frame-233 JPEG artifact (input SHA-256
  `d8e9ba607bde8bccb1bf812e7d0d354abf41a57c0461e6b59c1fa9d5dcc58888`),
  completed with exit 0, and its 3,934-byte terminal report is preserved as
  hashed evidence. Adapter tests cover argument validation, output
  collection, and failure/timeout propagation.
- M8 adds the release gates: a synthetic committed fixture
  (`tests/fixtures/http-smoke.pcap`, two hand-crafted HTTP frames), seven
  real-TShark tests (fixture smoke with rerun determinism, four malformed
  captures with bounded consistent outcomes, empty valid capture, and
  interrupted `running` body-task recovery on rerun), real-TShark CI on both
  matrix runners with a CLI analyze/report smoke step, MIT LICENSE,
  THIRD_PARTY_NOTICES.md, rewritten README, `docs/USER_GUIDE.md`,
  `docs/RELEASE_CHECKLIST.md`, `scripts/auto-shark-gui.cmd`, and the 0.1.0
  Beta version bump.
- Final v1 verification passes Ruff; Windows CPython 3.11.15 reports 208
  tests at 87 percent total coverage with real TShark 4.6.7; CPython 3.9.25
  reports 201 passed plus the expected widget skip, also with real TShark.
  `uv build` produces `auto_shark-0.1.0` containing `plugins.py`,
  `remote.py`, `assets/cwd_adapter.py`, the GUI package, and all reporting
  modules. M0 through M8 are complete; the project has reached its v1
  release goal.
- v0.1.0 is published at https://github.com/Monody12/auto-shark/releases/tag/v0.1.0
  with four assets: the out-of-the-box Windows bundle
  `AutoShark-0.1.0-Windows-x64.zip` (49,250,930 bytes, SHA-256
  `317d27c46d3c99e8ab1290e87f78b57b69d74fcbf7bb374463b1848500bad853`;
  PyInstaller onedir from the committed `scripts/autoshark.spec` with
  embedded Python 3.11 + PySide6, `AutoShark.exe` GUI and `auto-shark.exe`
  CLI, LICENSE/notices/install README), the wheel, the sdist, and
  SHA256SUMS. Packaged executables were smoke-tested locally end to end
  (probe, analyze, report, export, GUI startup). TShark stays a separate
  GPL install that the bundle auto-detects.
- Post-release CI hardening: real-TShark CI on GitHub Actions is green on
  both matrix jobs (Windows Python 3.11 with the choco Wireshark client plus
  the analyze/report CLI smoke, and Ubuntu Python 3.9 with the apt client)
  for run 31999186756. The first Ubuntu failure was a genuine cross-platform
  bug — `sftp_batch_text` used `Path.as_posix()`, which leaves backslashes in
  local Windows paths untouched on POSIX hosts — fixed by pure string
  replacement in `remote.py`; CI now also surfaces failing pytest lines as
  step annotations with fail-fast disabled.

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

## 2026-08-17 optimization checkpoint

- The previously pending product-surface work is now implemented in the
  working tree: image-artifact analyzer orchestration, HTTP transaction detail
  parameters in the GUI, report assessment/next-step hints, Linux
  `remote-setup` and `image-analyze` CLI surfaces, and a corpus expansion
  strategy are documented. The existing uncommitted work from the prior
  session was preserved and verified rather than reverted.
- Fixed a cwd-adapter regression where a bare inner argument such as `pass`
  was converted to a path merely because a same-named directory existed in the
  controller cwd. Only path-shaped arguments are now absolutized.
- Added the Windows dual-package release flow: `scripts/build_windows_release.ps1`,
  `scripts/windows_installer.iss`, `scripts/README-WINDOWS.txt`, and the tag
  workflow `.github/workflows/release.yml`. The installer has a stable AppId,
  per-user fixed directory, in-place `_internal` replacement, and preserved
  project data. The portable ZIP always has a top-level `AutoShark` directory.
- `uv.lock` now records the build group with PyInstaller 6.22.1. Windows
  CPython 3.11.15 full suite: 217 passed. Ruff: clean. Focused adapter,
  reporting, query, GUI-service, image-analysis, and packaging tests: 21
  passed.
- Real package build succeeded with PyInstaller 6.22.1 and Inno Setup 6.7.3.
  Final local artifacts are under `%LOCALAPPDATA%\AutoShark\releases\0.1.1-final`:
  installer 33,566,631 bytes SHA-256
  `baf9dc56217353f63ac705e9bc4ff1f73f8415f9320015cba43fd9afaa46a6ff`,
  portable ZIP 50,153,199 bytes SHA-256
  `727b5e1152152433300363d8196d9213ff820217bd58e8af3c7e1232e6dc54d2`,
  wheel SHA-256 `0e336e6adaf5ecfec3059fff7227a9db9d25ea036e3e408f2f4cc9254c8b99c4`,
  sdist SHA-256 `415d45e0dd8ec8998a7777b68b1ba13d72c1716e7ee26e49eb15dfe4c3eb1c4d`.
  Packaged CLI `--version`, real TShark probe, full fixture analyze/report,
  stable ZIP root, checksum manifest, and silent install/upgrade/uninstall
  smoke all passed. The upgrade smoke confirmed a stale `_internal` file was
  removed while the installed CLI reported `auto-shark 0.1.1`.
- Linux live validation: `remote-probe` confirmed `/usr/bin/python3`,
  `/usr/bin/file`, `/usr/bin/strings`, `/usr/local/bin/zsteg`, and `/usr/bin/7z`;
  `remote-setup` uploaded `.auto-shark-jobs/cwd_adapter.py`. The full toolkit
  run returned bounded `exit 124` after producing output and reported missing
  steghide/stegseek/outguess/jphide/openstego/foremost/gifsicle capabilities;
  no service was restarted or altered.

## 2026-08-17 corpus-driven protocol checkpoint

- Added `src/auto_shark/dns.py` and the `dns-triage` CLI/GUI stage. It uses
  payload-free TShark DNS query fields, groups bounded hex/Base32/Base64URL
  labels by route/base domain, records duplicate and byte-volume signals, and
  creates a persistent evidence/manual-queue item. Only a unique PNG with
  valid chunk CRCs is promoted to an artifact; uncertain streams remain
  bounded preview evidence.
- The BSides San Francisco CTF 2017 dnscap sample is stored locally under the
  user's practice corpus. Capture SHA-256 is
  `2913744793e3b95676d0713aef7c7df42ddb2f8ffece2b022c7ee727b833f59`.
  Real TShark 4.6.7 triage saw 220 encoded queries and 18,101 decoded bytes,
  found one score-100 `skullseclabs.org` group over frames 1-381, inferred a
  9-byte header, and recovered one 11,497-byte PNG. Recovered PNG SHA-256 is
  `d3ff9f96c3b0e1ed4f6f8dcc6dce07a33d5e223e8299340d35169980ca6809d7`.
- Clean runtime project
  `%LOCALAPPDATA%\AutoShark\projects\bsidessf-dnscap-20260817.auto-shark`
  passes SQLite integrity and foreign-key checks, has one DNS stream evidence
  row plus one precise `dns-carved-file` range (offset 95, length 11,497), one
  complete image artifact, one priority-100 manual task, and stable repeated
  report bytes (13,311 bytes,
  `987210e23d33cdeb667a3de6c49488e28520f94efda94cb0549f5b1b90e69232`).
  The earlier zero-task result is retained in the challenge write-up as the
  pre-detector gap; it is not the current behavior.
- Windows Python 3.11.15: Ruff clean, 226 tests passed. Python 3.9.25: 217
  passed and one expected GUI-widget skip. `uv build` succeeds and the wheel
  contains both `auto_shark/dns.py` and `auto_shark/voip.py`.
- Solved and saved the 2016 CFF 简单网管协议 sample at
  `C:\Users\Administrator\OneDrive\CTF\Question\Misc-pcap`:
  `2016cff_simple_snmp.pcapng`, 2,291,956 bytes, SHA-256
  `6c9791f0acf3af7edb36c99131c1307d74e06f7e32c4ef6b5ee6f11497d1db`.
  The 4,306-frame mixed capture contains 192 SNMP frames. Independent TShark
  inspection found frame 3588, community `public`, OID
  `1.3.6.1.2.1.1.6.0`, and the answer embedded in an OctetString. The local
  write-up and `solve_2016cff_simple_snmp.py` contain the answer; no answer
  file was used by Auto-Shark.
- A clean Auto-Shark run processed all 4,306 frames and produced 46 review
  tasks; the SNMP task was initially generic priority 40. The queue now emits
  a generic `snmp-sensitive-values` signal at priority 65 with bounded advice
  to inspect community/OID/OctetString values. It does not auto-extract SNMP
  flags or pretend to understand every MIB.

## 2026-08-17 TFTP corpus checkpoint

- Added `src/auto_shark/tftp.py` and the `tftp-extract` CLI/GUI stage. It uses
  one bounded discovery pass and a second pass over negotiated UDP routes,
  supports RRQ downloads and WRQ uploads, handles duplicates, conflicts,
  missing blocks, explicit server errors, byte/count budgets, and 16-bit block
  number wrap. Only complete, gap-free, conflict-free bytes become artifacts.
- PicoCTF 2021 Trivial Flag Transfer Protocol was solved and saved in the user
  practice corpus. Capture SHA-256 is
  `2cf17f1a8837fb25613743df5c9b5d1a0748c783bfc02980689443adebd94156`.
  Real TShark 4.6.7 extraction saw 19 discovery packets and 76,192 selected
  DATA packets, producing one WRQ upload, five complete RRQ downloads, and two
  `File not found` records with no malformed rows or exhausted budgets.
- The previously missed WRQ `instructions.txt` was recovered at frame 3.
  `picture2.bmp` crossed block `65535 -> 0` and reconstructed to 36,578,358
  bytes, SHA-256
  `8cb8135856261596696a625efb5850778013f0e7ea5caeb5f6ba6a2de30f0308`.
  The local no-answer-constant solver derives `DUEDILIGENCE` from ROT13 text;
  an actual StegSeek 0.6 run recovered the final file from `picture3.bmp`.
- Focused TFTP, GUI-stage, queue, and reporting regression is 26 tests passed.
  Full Windows Python 3.11 regression with real TShark is `254 passed`;
  Python 3.9 is `244 passed, 1 skipped` (optional GUI extra). Ruff and
  `uv build` pass, `git diff --check` reports no whitespace error, and the
  wheel contains `auto_shark/tftp.py`, `icmp.py`, `dns.py`, and `voip.py`.

## Next executable step

Complete and publish the v0.2.0 release, then continue simple/medium non-SQLi
BUUCTF traffic challenges from the supplied practice dashboard. Record
attachment availability separately from write-up-only evidence, save solved
captures and Chinese write-ups in the user's practice corpus, and only add
generalizable analyzers when real captures expose a bounded gap. The one-time
independent clean-machine GUI acceptance and a lightweight Linux analyzer
manifest (`file`, `strings`, or `zsteg`) remain useful follow-up validation.

## 2026-08-17 HTTP/TLS/Telnet corpus checkpoint

- Fresh Struts2 validation recognizes `{FLAG:...}` as a rank-99 candidate and
  rejects the prior CSS `key{color:...}` false positive. The new bounded OGNL
  detector inspects URL-form field names, extracts `ProcessBuilder` commands,
  persists three `web-command-execution` events at request frames 1365, 1387,
  and 1444, links response frames 1367, 1389, and 1446, marks the repeated
  command as a duplicate, and emits one critical endpoint finding. The
  detector is included in `detect`; `timeline --detector` exposes its events.
- The undecrypted Hack Dat Kiwi TLS baseline remains opaque by design. After
  inventory, its manual queue emits `tls-encrypted-traffic` at priority 55 and
  explains key-log/RSA input plus the ECDHE/TLS 1.3 boundary. Auto-Shark still
  does not accept TLS key material or claim decryption.
- Solved and saved `2016cff_remote_login_telnet.pcapng` (18,534,380 bytes,
  SHA-256 `d4266c1bf52913f0b89cd037ad5dc05927a3ba1446076ab4bea234a499eceb11`)
  with a no-answer-constant script and Chinese write-up. The 24,271-frame
  mixed capture has one complete Telnet stream: 636 metadata frames, 357
  client bytes, 70,154 server bytes, and four server-side flag candidates.
- The Telnet parser is now version 2. Bare CR is a line terminator while
  CRLF and CR-NUL stay in one exact record. Real rerun restores
  `prompt:login -> ira\r` and `prompt:password -> filename.txt\r`
  `responds-to` relations while retaining Tab/backspace controls and exact
  frame/source mappings. Focused Telnet tests report 9 passed.

## 2026-08-17 bilingual and side-channel checkpoint

- The optional Qt client now detects Chinese Windows/Linux locales and uses
  Simplified Chinese; all other, missing, or unknown locales fall back to
  English. `AUTO_SHARK_LANGUAGE=zh-CN|en-US` remains a test override. Startup
  errors and staged-analysis titles use the same translation layer.
- Added `tcp-urgent` detector/CLI/GUI stage. It groups non-zero
  `tcp.urgent_pointer` values by stream and direction, preserves source frame
  ranges, emits printable text and flag-shaped candidates, and records a
  high-confidence finding when the sequence is printable.
- Added `usb-hid` detector/CLI/GUI stage. It inventories endpoint report
  lengths, applies conservative Boot Keyboard checks (reserved byte, release
  reports, known key-code ratio), recognizes supported absolute-coordinate /
  pressure report series, and emits cross-device frame/time correlation hints.
- Solved and saved two additional broad-practice captures under
  `C:\Users\Administrator\OneDrive\CTF\Question\Misc-pcap`:
  Google CTF 2016 A Cute Stegosaurus (`google_ctf_2016_a_cute_stegosaurus.pcap`,
  SHA-256 `10a1c947de99a5de658f91d3cbf147078226673b2406b244b49df5035ac1ae19`),
  where TCP urgent pointers spell
  `CTF{And_You_Thought_It_Was_In_The_Picture}`, and LCTF 2018 osu!
  (`lctf_2018_osu_usb.pcap`, SHA-256
  `30e2a568c25c656a2442c8c509195cf718e31a510652796935e0e6434d6caaa0`),
  where HID keyboard C-key windows select Wacom pen strokes spelling
  `LCTF{OSU_IS_GOOD}`. Each capture has a no-answer-constant solver and a
  Chinese write-up; the LCTF directory also contains the verified recovered
  PNG.
- Windows Python 3.11.15 + PySide6 6.11.1 + real TShark release-gate run:
  `246 passed`, Ruff clean, `git diff --check` clean, and source/wheel builds
  succeed with `UV_LINK_MODE=copy` for OneDrive compatibility. Python 3.9.25
  core run: `228 passed, 8 skipped` (GUI extra/TShark unavailable in that
  isolated environment).

## 2026-08-17 ICMP oracle corpus checkpoint

- Added `src/auto_shark/icmp.py` plus the `icmp-triage` CLI/GUI stage. It uses
  structured TShark fields and explicit `icmp.resp_to` links to recognize
  printable, varying request-TTL series with both answered and unanswered
  probes. It preserves the exact frame/field evidence and does not infer
  uncaptured guesses or emit a flag candidate.
- Solved and saved Insomni'hack CTF 2015 Time to leak in the local practice
  corpus. Capture SHA-256 is
  `c9549814f2b9cef6c44e069678e3d3c6a08198973d315f05193480aef2f41f4c`.
  The 22-packet capture contains 14 requests whose TTL values spell
  `RSTUTRTSTTKTTL`; explicit replies produce bitmap `00101010110111`. The
  capture is only a middle excerpt, so the complete historic answer is kept
  in the write-up as external evidence rather than claimed as recovered.
- Real triage produces one score-100 `icmp-ttl-oracle` finding over frames
  1-21 and stays idempotent. A 2,048-packet MsPing capture with fixed TTL 64
  is the negative control and produces no finding.
- Final verification: Windows Python 3.11 with real TShark reports
  `251 passed`; Python 3.9 reports `234 passed, 8 skipped`; Ruff and
  `uv build` pass. The built wheel contains `auto_shark/icmp.py`,
  `auto_shark/dns.py`, and `auto_shark/voip.py`.

## 2026-08-17 BUUCTF easycap TCP-text checkpoint

- The interrupted BUUCTF `sqltest` capture is preserved as
  `buuctf_sqltest.pcapng` (2,274,484 bytes, SHA-256
  `153412ba27407452ddd419d81e1d1f3a523940dae1317faefe3bcb13c6069287`)
  with `buuctf_sqltest_未完成记录.md` in the local practice corpus. It is
  explicitly not solved: the record stops after passive identification of 972
  GET request/response pairs and two stable response lengths. No recovered
  database values, final flag, or solver are claimed.
- Solved and saved BUUCTF `easycap` as `buuctf_easycap.pcap` (6,802 bytes,
  SHA-256 `5e1cb4ad2dd6aef750654f5377d9e67ed2732b97fe64d56e0603242c4b87d921`)
  with `solve_buuctf_easycap.py` and `buuctf_easycap_题解.md`. The no-answer-
  constant solver independently reassembles first-seen TCP bytes by raw
  sequence and reports the captured `FLAG:` value over frames 4-76.
- Added bounded `tcp-text` CLI/GUI triage. It selects only generic TCP/`data`
  conversation profiles, excludes recognized application protocols, applies
  per-stream/count/total budgets, reuses current TCP reconstruction and triage,
  updates `data` coverage, and rebuilds the manual queue. Known-format search
  now accepts explicit unbraced `FLAG:<mixed-token>`-style values while
  requiring both letters and digits and deferring chunk-end matches.
- Clean runtime project
  `%LOCALAPPDATA%\AutoShark\projects\buuctf-easycap-tcptext-20260817.auto-shark`
  automatically refreshed inventory, selected stream 0, reconstructed 38
  bytes with no gaps/conflicts, and emitted one rank-100 candidate. Its exact
  candidate evidence is offset 0, length 37, frames 4-76, with all 37 source
  frames listed; `data` coverage is `complete`.
- Focused verification is Ruff clean and 34 tests passed across search,
  triage, TCP-text, GUI services, and CLI. Final Windows Python 3.11.15 with
  real TShark reports `257 passed`; Python 3.9.25 reports `247 passed, 1
  skipped` (optional GUI extra). `uv build` and `git diff --check` pass. Wheel
  SHA-256 is `f5e462523f71a05b76942c6c8524372398020f647f2143d67d11f6c700e5faf0`
  and it contains `auto_shark/tcp_text.py`, `search.py`, and `triage.py`.
- The clean real project passes SQLite integrity and foreign-key checks. Its
  one conversation profile, one current TCP reconstruction, one candidate,
  and one candidate-evidence link are stable; all 22 content-addressed Blobs
  independently rehash with zero mismatches.

## 2026-08-18 v0.2.0 release checkpoint

- The release version is 0.2.0 because this work adds substantial functional
  surface beyond v0.1.1: bilingual GUI behavior, DNS/ICMP/TFTP/VoIP/TCP-text,
  TCP urgent-pointer, USB HID, OGNL and image analysis, plus installer and
  portable delivery. It is not a patch-only release.
- The final audit fixed both legacy and new-code defects: leaked SFTP batch
  files, a missing frozen remote adapter, image-analysis starvation, DNS PNG
  aggregate budget overflow, unverified/unbounded OGNL Blob reads, unbounded
  HTTP details, CLI tracebacks for tool errors, missing side-channel tool-run
  provenance, incorrect budget statuses, stale manual queue entries, missing
  post-stage queue refreshes, RTP conflicting retransmissions, and incomplete
  TCP reconstruction coverage.
- Final source gates pass: Ruff, compileall, and `git diff --check`; Windows
  Python 3.11.15 with real TShark 4.6.7 reports `274 passed`; Python 3.9.25
  reports `264 passed, 1 skipped` for the intentionally absent GUI extra.
- The local v0.2.0 release candidate contains installer, portable ZIP, wheel,
  sdist, and verified `SHA256SUMS`. SHA-256 values are: installer
  `602f2922275c90c70031987b2b262ebc18312a918207a911a0c8b4ba0e405eae`,
  portable ZIP
  `1368266fa68103446bcd97ee28aac61f9fe5e4faa7f9ff21a9835b64cf3401cb`,
  wheel `5fedd525844129cc62f2d05741de044d04cc1425f07b6e2e06c40bd856be9780`,
  and sdist `d08fde30a4d05b788e6cf70b27f55070cf249595753afb24709f85caa198ccc6`.
- Frozen CLI version/probe/analyze/report and offscreen GUI startup pass. A
  real v0.1.1-to-v0.2.0 installer upgrade removed a stale `_internal` marker,
  preserved the project, and read it successfully; uninstall removed the app
  while preserving the project and report. The independent Windows 11 clean-
  machine exercise remains explicitly pending in `docs/RELEASE_CHECKLIST.md`.
- Commit `a3b1adc` is tagged `v0.2.0` and published at
  https://github.com/Monody12/auto-shark/releases/tag/v0.2.0. GitHub Actions
  run `32087142678` completed successfully and uploaded five assets.
- All four published artifacts were downloaded and rehashed against the
  published `SHA256SUMS`: installer
  `2965bdcc584d2146479d69f01cb2598f0363ce2710ddf5cccf5a5adb49ab1783`,
  portable ZIP
  `181b4a22eeca8b9276dd43ca85e165ad4ac8a306cf775a2c8e6d7bbf99c320ac`,
  wheel `fe261a20b601bc2c9400f6422bb702fbc3a074a011c4e615f17a0ff9568a5d2f`,
  and sdist `5c0a8d3fa104d0c782edd43a8826d9d3f35f5440ac1d9e06c9b13b23e7c45e2d`.
  The downloaded wheel/runtime contents, portable CLI probe, adapter, and
  offscreen GUI startup all pass.
