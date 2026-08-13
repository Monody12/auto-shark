# Auto-Shark Project State

Updated: 2026-08-13, Asia/Shanghai

This is the canonical resume checkpoint. Update it after every tested slice.

## Objective

Deliver the v1 offline CTF packet-analysis workbench defined in `AGENTS.md` and
`docs/ARCHITECTURE.md`, with a Python 3.9+ CLI core, Windows/Python 3.11 GUI,
TShark structured parsing, bounded on-disk evidence processing, explainable
candidate ranking, static file analysis, and constrained optional Linux jobs.

## Current milestone

M2 - streaming TShark ingestion, HTTP/TCP reconstruction, and search pipeline.

Status: active. M0 and M1 exit criteria are complete.

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

## Verification at this checkpoint

Environment paths below are local evidence, not production defaults:

- `UV_PROJECT_ENVIRONMENT=C:\Users\Administrator\AppData\Local\AutoShark\venvs\dev`
- `uv sync --all-groups`: succeeded with CPython 3.11.15.
- `uv run ruff check .`: all checks passed.
- `uv run pytest --cov=auto_shark --cov-report=term-missing`: 14 passed,
  total coverage 68 percent on Windows Python 3.11.15.
- Separate environment `...\venvs\py39`; `uv sync --python 3.9 --all-groups`
  and `uv run pytest -q`: 42 passed on CPython 3.9.25 after M2 slice 3.
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
- Parent repository status after migration no longer lists `auto-shark/` and
  retains the pre-existing `.idea`, archive cache, and `pyshark/` changes.

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
- High-confidence known-format search currently recognizes explicit `flag`,
  `ctf`, `key`, and `answer` prefixes. Unknown-format triage remains a separate
  detector so preceding printable bytes are not swallowed into a false value.
- Candidate links point to `flag-match` evidence with exact byte offset/length,
  which in turn references the parent evidence/blob; they do not merely point
  at the whole body.
- Both URL-form decoding and second-layer Base64/hex output count against the
  configured per-output and total transform byte budgets. Over-budget raw field
  slices remain evidence, but no decoded blob or transform is created.

## Risks and constraints

- The local `ctf-stego-toolkit` currently lacks the required JSON/output-dir
  contract. That cross-project change needs its own explicit implementation
  checkpoint before remote integration.
- Linux Python 3.9 validation requires the verified remote node or CI runner;
  current local development validates Windows Python 3.11.
- PyCharm was not found in the standard install/registry locations. It is not a
  build prerequisite and no installation is planned automatically.

## Next executable step

Implement M2 slice 4: automatic bounded body selection/extraction for indexed
HTTP transactions plus TCP stream reconstruction evidence. Add protocol-aware
body priority, total extraction budget, progress/failure persistence, and a
single `analyze --with-bodies --scan` workflow. Validate all 19 WebShell target
transactions and preserve the ZIP-bearing response without manual frame lists.
