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

## Verification at this checkpoint

Environment paths below are local evidence, not production defaults:

- `UV_PROJECT_ENVIRONMENT=C:\Users\Administrator\AppData\Local\AutoShark\venvs\dev`
- `uv sync --all-groups`: succeeded with CPython 3.11.15.
- `uv run ruff check .`: all checks passed.
- `uv run pytest --cov=auto_shark --cov-report=term-missing`: 14 passed,
  total coverage 68 percent on Windows Python 3.11.15.
- Separate environment `...\venvs\py39`; `uv sync --python 3.9 --all-groups`
  and `uv run pytest -q`: 14 passed on CPython 3.9.25.
- `auto-shark probe --tshark <portable 4.6.7>`: usable; HTTP, HTTP export,
  TCP reassembly, FTP, FTP-DATA export, Telnet, and multipart all available.
- A real `networking.pcap` project was created and reopened under
  `%LOCALAPPDATA%\AutoShark\projects`; it recorded SQLite schema 1, 4,570 bytes,
  and SHA-256 `7072e7e1a42efe6b77bc0a428b5297440f123098143e830c1e9b7c7ae6886165`.
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

## Risks and constraints

- The local `ctf-stego-toolkit` currently lacks the required JSON/output-dir
  contract. That cross-project change needs its own explicit implementation
  checkpoint before remote integration.
- Linux Python 3.9 validation requires the verified remote node or CI runner;
  current local development validates Windows Python 3.11.
- PyCharm was not found in the standard install/registry locations. It is not a
  build prerequisite and no installation is planned automatically.

## Next executable step

Implement M2's streaming TShark metadata adapter and persistence transaction:
record the capability/tool run, ingest frame and HTTP request/response facts
line by line, pair transactions by `http.response_in`/`http.request_in`, expose
`auto-shark analyze`, and validate the 19 WebShell pairs without loading all
TShark decoded output into memory.
