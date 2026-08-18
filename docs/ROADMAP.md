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

## M3 - FTP, Telnet, files, and unknown triage (complete, estimate 4 days)

- FTP control/PASV/data correlation and static export.
  Status: complete with explicit setup/command frame correlation, bounded TCP
  reuse, exact `ftp-data` evidence, budget states, and unreviewed static
  artifacts. Transferred archive contents are not opened.
- Directional Telnet dialogue reconstruction.
  Status: complete with initial-SYN endpoint roles, incremental RFC 854 byte
  parsing, exact TCP source ranges, prompt/input/echo relations, explicit
  bounded states, candidate linkage, and stable bounded JSON queries.
- File magic, declared/actual type mismatch, structural end, trailing-data scan.
  Status: complete for reusable bounded carving over HTTP/transform evidence,
  conservative multipart correlation, declared/actual type mismatch findings,
  structural ends, trailing ranges, and persistent manual triage.
- Protocol/conversation summary and manual-analysis queue.
  Status: complete with schema 11 capture inventory, schema 12 compatibility
  repair, bounded protocol/conversation profiles, explicit coverage states,
  conservative multipart correlation, HTTP status/body contradiction findings,
  and persistent idempotent manual queue plus summary/queue/state CLI queries.

## M4 - CTF detectors and CLI acceptance (complete, estimate 4 days)

- Known flag search and unknown flag-like candidate rules.
  Status: complete with bounded exact-range detection, conservative false-positive
  exclusions, stable ranking, rerun provenance, and manual-queue integration.
- SQL injection behavior reconstruction.
  Status: complete for bounded query/form inputs, static multi-signal detection,
  clean-request comparisons, partial confidence caps, stable events/findings,
  public-sample acceptance, and explicit failure/budget provenance.
- WebShell detection, decoded operation timeline, and deduplication.
  Status: complete with persisted-transform-only static classification,
  normalized target timelines, semantic repeat groups, and bounded queries.
- All five acceptance captures pass without detectors reading answer oracles.
  Status: complete under the schema 13 contract in
  `docs/M4_IMPLEMENTATION.md`, including public SQL-sample provenance and the
  exact 19-event/eight-group WebShell acceptance result.

## M5 - Investigation state and reports (complete, estimate 3 days)

- Review states and notes.
  Status: complete with schema 14 capture-scoped notes, legacy preservation,
  current-subject validation, bounded queries, and explicit CLI mutations.
- Stable machine-readable JSON schema.
  Status: complete with bounded `auto-shark.report/v1` JSON, independent
  collection budgets, path/Blob-byte redaction, and deterministic ordering.
- Self-contained offline HTML and evidence directory export.
  Status: complete with staged atomic publication, new/empty destination
  enforcement, hash manifest, exact bounded evidence ranges, explicit
  missing/incomplete/over-budget skips, and an offline script-free HTML shell.
- Reopen/export determinism and provenance validation.
  Status: complete; repeated reports and two fresh-directory exports are
  byte-identical across all five acceptance projects with integrity,
  foreign-key, and empty-jobs checks recorded in `PROJECT_STATE.md`.

## M6 - PySide6 investigation UI (complete, estimate 6 days)

- Project creation/opening and analysis progress/cancellation.
  Status: complete with a lazy `gui` CLI entry, open/create dialogs, a
  `QThread` staged pipeline runner, per-stage progress with summaries, and
  cooperative between-stage cancellation that never kills bounded work.
- Overview, paired HTTP, streams/messages, search, findings, files, lineage.
  Status: complete through nine bounded pages (overview metrics and report
  JSON, HTTP transactions with URI filter and pagination, streams, Telnet
  dialogues with record detail, candidates/findings with signal and evidence
  detail, WebShell timeline, manual queue, notes, and export); candidate
  search results surface through the bounded findings query.
- Notes/review workflow and report export.
  Status: complete with note add/update, review-mark upsert, manual-task
  state changes, and offline bundle export with manifest and skip reporting.
- Responsive Windows desktop behavior and empty/error/partial states.
  Status: complete for construction, rendering, empty/error/truncation
  states, and real-sample rendering verified offscreen on Windows Python
  3.11; interactive desktop acceptance remains part of M8 clean-machine
  validation.

## M7 - Plugins and Linux enhancement node (complete, estimate 5 days)

- Plugin manifest and in-process/external adapter limits.
  Status: complete under the schema 15 contract in `docs/M7_IMPLEMENTATION.md`:
  validated `auto-shark.plugin/v1` manifests, placeholder-only argument
  lists, bounded limits, isolated job directories, and hashed outputs with
  explicit skips.
- Stable JSON report/output-dir support for `ctf-stego-toolkit`.
  Status: complete through the shipped working-directory adapter
  (`auto_shark/assets/cwd_adapter.py`): the toolkit runs unmodified inside
  the isolated output directory, its terminal report is preserved verbatim
  as hashed `stdout.txt`/`stderr.txt` evidence, and terminal prose is never
  parsed into structured conclusions.
- Local image adapter and constrained SSH/SFTP runner.
  Status: complete with the injectable `RemoteTransport`, charset-constrained
  ssh/sftp argument-list transport, absolute remote-executable probing,
  request/result hash persistence into `remote_job`, and explicit fetch/
  limit skips. The configured CentOS node was probed successfully and the
  adapter was uploaded; a full ctf-stego-toolkit run was bounded at 120 seconds
  after producing outputs, so lightweight per-tool jobs remain the recommended
  live-node path.
- Capability probing, isolation, timeout, output cap, hash verification tests.
  Status: complete for local runs, the adapter, and the remote runner under
  the fake transport; live-node equivalents run during real-node validation.

## M8 - Packaging and release validation (complete, estimate 4 days)

- Windows launcher/package, licenses, notices, and clean-machine install test.
  Status: complete except the one-time hands-on clean-machine run: MIT
  LICENSE, THIRD_PARTY_NOTICES.md, `scripts/auto-shark-gui.cmd`, version
  0.2.0 Beta, stable-root portable ZIP, stable-AppId per-user installer,
  README/user guide, and the scripted clean-machine procedure in
  `docs/RELEASE_CHECKLIST.md`.
- Windows TShark 4.6.7 and Linux supported-profile CI.
  Status: complete; CI installs real TShark on both matrix runners, runs the
  full suite with `AUTO_SHARK_TSHARK`, and smoke-analyzes the committed
  synthetic fixture capture.
- Large/malformed capture resource tests and interruption recovery.
  Status: complete for malformed/short/empty captures (bounded, rerun-stable,
  explicit tool-run states) and interrupted `running` body-task recovery on
  rerun; large-input budgets were already covered at M2.
- User documentation and v1 release checklist.
  Status: complete; `docs/USER_GUIDE.md` and `docs/RELEASE_CHECKLIST.md`
  record verified evidence and the two user-executable residuals (clean
  machine test, live Linux node).

## v0.2.0 - Extended traffic triage and Windows delivery (complete)

- Added bounded DNS, ICMP, TFTP, RTP/G.711, TCP urgent-pointer, USB HID,
  generic TCP-text, OGNL, and image-analysis workflows with CLI/GUI stages,
  provenance, budgets, artifacts, findings, and manual-queue integration.
- Added Simplified Chinese GUI localization with English fallback and automatic
  locale selection on supported Windows/Linux desktops.
- Added a stable-AppId Windows installer, stable-root portable archive,
  deterministic checksums, and a tag-triggered GitHub Release workflow.
- Completed the pre-release regression and hardening pass across legacy and new
  code: bounded HTTP detail output, verified Blob reads, side-channel tool-run
  provenance, RTP conflict handling, incomplete TCP reconstruction coverage,
  stale manual-task filtering, SFTP batch cleanup, and frozen adapter inclusion.
