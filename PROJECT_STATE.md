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

## Verification at this checkpoint

Environment paths below are local evidence, not production defaults:

- `UV_PROJECT_ENVIRONMENT=C:\Users\Administrator\AppData\Local\AutoShark\venvs\dev`
- `uv sync --all-groups`: succeeded with CPython 3.11.15.
- `uv run ruff check .`: all checks passed.
- `uv run pytest --cov=auto_shark --cov-report=term-missing`: 14 passed,
  total coverage 68 percent on Windows Python 3.11.15.
- Separate environment `...\venvs\py39`; `uv sync --python 3.9 --all-groups`
  and `uv run pytest -q`: 35 passed on CPython 3.9.25 after M2 slice 2.
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

## Risks and constraints

- The local `ctf-stego-toolkit` currently lacks the required JSON/output-dir
  contract. That cross-project change needs its own explicit implementation
  checkpoint before remote integration.
- Linux Python 3.9 validation requires the verified remote node or CI runner;
  current local development validates Windows Python 3.11.
- PyCharm was not found in the standard install/registry locations. It is not a
  build prerequisite and no installation is planned automatically.

## Next executable step

Implement M2 slice 3: streaming printable/raw flag search over body blobs plus
bounded URL-form, Base64/Base64URL, and hex transforms. Persist transform
lineage and candidate evidence/ranking, never execute decoded content, and
validate that WebShell form parameters decode without placing full bodies in
SQLite. Include chunk-boundary matches and the embedded ZIP offset as tests.
