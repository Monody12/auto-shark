# Roadmap

Status values: pending, active, complete. A milestone is complete only after
all exit criteria are verified and recorded in `PROJECT_STATE.md`.

## M0 - Repository and runnable skeleton (complete, estimate 1 day)

- Standalone Git repository and OneDrive-safe ignore policy.
- Durable recovery/checkpoint documentation.
- Python 3.9+ package managed by uv; developer tools and Windows 3.11 workflow.
- Runnable `auto-shark --help`, version command, typed configuration, and tests.
- CI definitions for Windows 3.11 and Linux 3.9.

## M1 - Evidence foundation and TShark probing (complete, estimate 4 days)

- Stable public IDs and evidence dataclasses.
- Versioned SQLite schema, migration tests, WAL/foreign-key validation.
- Content-addressed blob writer with atomic finalization and hash verification.
- Safe subprocess runner and structured TShark capability profile.
- Project create/open/status CLI with machine-local path guardrails.

## M2 - HTTP/TCP and search pipeline (complete, estimate 5 days)

- Streaming TShark metadata ingestion and persisted tool-run provenance.
  Status: complete for HTTP-over-TCP metadata.
- Precise HTTP request/response pairing across keep-alive connections.
  Status: complete, including unmatched/orphan/extra-response representation.
- On-demand bounded body extraction and TCP reconstruction.
  Status: HTTP body extraction and automatic transaction scheduling complete;
  bounded per-direction TCP reconstruction is complete, including exact
  retransmission, conflict, gap, budget, and frame-range provenance.
- Raw/text/field search plus URL, Base64/Base64URL, and hex lineage.
  Status: complete for extracted HTTP bodies and URL-form fields.
- Explainable candidate normalization, ranking, and deduplication.
  Status: complete for known-format and structured authentication-field
  triage, with stable bounded transaction/stream query surfaces and versioned
  score signals. Generic unstructured unknown-token heuristics remain M4 scope.

## M3 - FTP, Telnet, files, and unknown triage (active, estimate 4 days)

- FTP control/PASV/data correlation and static export.
  Status: complete with explicit setup/command frame correlation, bounded TCP
  reuse, exact `ftp-data` evidence, budget states, and unreviewed static
  artifacts. Transferred archive contents are not opened.
- Directional Telnet dialogue reconstruction.
  Status: complete with initial-SYN endpoint roles, incremental RFC 854 byte
  parsing, exact TCP source ranges, prompt/input/echo relations, explicit
  bounded states, candidate linkage, and stable bounded JSON queries.
- File magic, declared/actual type mismatch, structural end, trailing-data scan.
  Status: reusable bounded carving is complete for HTTP/transform evidence;
  general protocol correlation, type mismatch, and manual triage remain M3.
- Protocol/conversation summary and manual-analysis queue.
  Status: complete with schema 11 capture inventory, schema 12 compatibility
  repair, bounded protocol/conversation profiles, explicit coverage states,
  conservative multipart correlation, HTTP status/body contradiction findings,
  and persistent idempotent manual queue plus summary/queue/state CLI queries.

## M4 - CTF detectors and CLI acceptance (pending, estimate 4 days)

- Known flag search and unknown flag-like candidate rules.
- SQL injection behavior reconstruction.
- WebShell detection, decoded operation timeline, and deduplication.
- All five acceptance captures pass without detectors reading answer oracles.

## M5 - Investigation state and reports (pending, estimate 3 days)

- Review states and notes.
- Stable machine-readable JSON schema.
- Self-contained offline HTML and evidence directory export.
- Reopen/export determinism and provenance validation.

## M6 - PySide6 investigation UI (pending, estimate 6 days)

- Project creation/opening and analysis progress/cancellation.
- Overview, paired HTTP, streams/messages, search, findings, files, lineage.
- Notes/review workflow and report export.
- Responsive Windows desktop behavior and empty/error/partial states.

## M7 - Plugins and Linux enhancement node (pending, estimate 5 days)

- Plugin manifest and in-process/external adapter limits.
- Stable JSON report/output-dir support for `ctf-stego-toolkit`.
- Local image adapter and constrained SSH/SFTP runner.
- Capability probing, isolation, timeout, output cap, hash verification tests.

## M8 - Packaging and release validation (pending, estimate 4 days)

- Windows launcher/package, licenses, notices, and clean-machine install test.
- Windows TShark 4.6.7 and Linux supported-profile CI.
- Large/malformed capture resource tests and interruption recovery.
- User documentation and v1 release checklist.
