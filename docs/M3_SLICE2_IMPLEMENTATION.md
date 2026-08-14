# M3 Slice 2 Telnet Implementation Contract

Status: complete and verified as of 2026-08-13, Asia/Shanghai.

This slice adds bounded directional Telnet dialogue records over the existing
TCP reconstruction. It must preserve every reconstructed byte and exact source
mapping without duplicating stream blobs.

## Verified sample facts

- The acceptance capture is `networking.pcap`, 4,570 bytes, 59 frames, SHA-256
  `7072e7e1a42efe6b77bc0a428b5297440f123098143e830c1e9b7c7ae6886165`.
- TShark 4.6.7 identifies only TCP stream 0 as Telnet. Its 36 payload frames
  contain 310 bytes and have no retransmission, spurious-retransmission,
  out-of-order, or lost-segment marker.
- The current client direction is complete, gap-free, conflict-free, and not
  midstream: 124 bytes from frames 4-52, SHA-256
  `7bf3a3d8c8d8664c12f6c527e809b10a4b76ce28a778f20ca5dff5eae1f6b700`.
- The current server direction is complete, gap-free, conflict-free, and not
  midstream: 186 bytes from frames 6-55, SHA-256
  `420bcf53bf0f7cf10f9795d4c2b053543b5aacc23280cdeeba40b3067c0656cb`.
- The login prompt is server output `[71,107)` at frame 22. Username input plus
  CRLF is client output `[76,82)` from frames 24, 27, 30, 33, and 36. Its four
  printable bytes are echoed individually by server frames 25, 28, 31, and 34.
- The password prompt is server output `[113,123)` at frame 39. Password input
  plus CRLF is client output `[82,122)` from frames 41 and 43. The existing
  known-format candidate remains exactly `[82,120)`, length 38, with frame 41
  as its sole primary source.
- Client bytes `[122,123)` and `[123,124)` are controls `0x04` and `0x03` from
  frames 49 and 52. Server bytes `[182,184)` are `IAC DM` (`ff f2`) split over
  frames 53 and 54; `[184,186)` is printable `^C` from frame 55.
- TShark `telnet.data` is not a byte-accurate primary source for the split
  `IAC DM`: it exposes the second byte as replacement text. Current TCP blobs
  and `tcp_reconstruction_source` are therefore authoritative. TShark Telnet
  fields are used for capability and protocol selection only.
- The existing schema 8 Telnet runtime project passes `integrity_check`, has no
  foreign-key violations, and has an empty `jobs` directory. No answer file or
  unrelated capture artifact was read during inspection.

## Byte and role contract

- A dialogue references one TCP conversation and its two current directional
  reconstructions. It never stores a second copy of reconstructed bytes.
- Client/server roles come from the capture's initial non-ACK SYN endpoint.
  If that evidence is unavailable, status is `unresolved-role`; port 23 alone
  is not sufficient to invent roles.
- Each direction is parsed independently as a byte stream. Directional records
  are then ordered by the minimum source frame, source time, direction, and
  stream range to form a deterministic capture timeline.
- Every nonempty byte in an accepted reconstruction belongs to exactly one
  record. Records may be application data, negotiation, subnegotiation,
  command, or incomplete-control. Binary and C0 control bytes are preserved.
- Application records retain their original stream ranges. Line endings,
  CR-NUL, direction changes, prompts without newlines, and control boundaries
  may affect semantic grouping but are never discarded or normalized in the
  authoritative range.
- Source mappings are intersections with `tcp_reconstruction_source` primary
  ranges. A record can span frames and one frame can contribute to multiple
  records. Duplicate sources remain TCP-layer provenance and are not copied.

## RFC 854 parser contract

- Parse incrementally across chunk and source-frame boundaries. Supported
  states cover ordinary data, `IAC IAC`, `WILL`, `WONT`, `DO`, `DONT`, single
  commands, `SB ... IAC SE`, escaped IAC inside subnegotiation, and truncated
  command/subnegotiation tails.
- A split sequence such as sample frames 53/54 must become one command record,
  not replacement text or two unrelated records.
- Unknown commands and options remain numeric and auditable. Parser behavior
  must not depend on localized TShark display strings.
- Preview rendering is a separate bounded query concern. It uses reversible
  escapes for control/non-UTF-8 bytes and never changes stored ranges.

## Schema 10 contract

- `telnet_dialogue` stores stable conversation identity, client/server
  endpoints, the two current reconstruction references, status, and update
  time. Status distinguishes `indexed`, `complete`, `partial`, `conflicting`,
  `truncated`, `unresolved-role`, and `failed`.
- `telnet_dialogue_run` preserves each indexing policy, tool-run provenance,
  status, record/byte counts, truncation, and error without changing stable
  dialogue identity.
- `telnet_metadata_skip` records each parsed Telnet frame excluded by the
  metadata-frame limit, including capture, frame, stream, tool run, and reason.
- `telnet_record` stores the reconstruction, direction role, record kind,
  `[start,end)` output range, semantic label, optional command/option, and
  source frame/time bounds. Stable identity is based on reconstruction ID,
  range, kind, and parser version.
- `telnet_record_source` maps every record range to its contributing TCP
  segment and exact record/stream subrange.
- `telnet_record_relation` stores explicit `responds-to` and exact-byte
  `echo-of` relations. Echo recognition never removes either side.
- `telnet_parse_skip` records every unprocessed reconstruction range and reason
  when stream, record, or byte budgets prevent full parsing.
- Application records may reference range evidence over the existing TCP blob.
  Negotiation/control records may remain range metadata. No new blob is
  created solely for a Telnet record.
- A rerun with the same current reconstructions and parser version preserves
  stable dialogue, record, evidence, source, and relation rows. Run provenance
  may append. Rebuilt TCP directions invalidate stale Telnet rows through
  current-reconstruction comparison before query output.

## Sequencing and bounded semantics

- A server application record ending in a colon plus optional ASCII spacing,
  without a completed line ending, may be labeled `prompt`. The final bounded
  token before the colon becomes a normalized prompt label such as `login` or
  `password`; this is structural parsing, not answer-specific detection.
- The next complete client application line after a prompt may be linked as
  `responds-to`. A later prompt, server failure/status line, or unambiguous
  control boundary closes the pending relation. Ambiguous input remains
  unlinked rather than guessed.
- Server application bytes exactly equal to preceding client application bytes
  may receive `echo-of`. Partial, transformed, or case-insensitive matches are
  not labeled as echoes.
- Existing candidates are joined by evidence blob plus overlapping byte range.
  The Telnet layer does not create, normalize, or rescore flag candidates.
- Positive limits cover candidate streams, records, bytes per direction, total
  parsed bytes, preview bytes per record, and total preview bytes. Every
  selected but unprocessed range is represented by a skip or truncated state.

## CLI and query contract

- `auto-shark index-telnet <project> --tshark <path>` selects bounded Telnet
  streams through structured TShark metadata, reuses bounded TCP
  reconstruction, parses current complete or explicitly degraded directions,
  and emits `auto-shark.telnet-index/v1` summary JSON.
- `auto-shark telnet-dialogues <project> [--stream N] [--offset N] [--limit N]`
  emits `auto-shark.telnet-dialogues/v1` with deterministic pagination. Query
  output includes status, endpoint roles, reconstruction/blob identity,
  records, ranges, source frames, relations, candidate references, and bounded
  escaped previews. It never inlines full blobs.
- Querying applies known append-only migrations but otherwise does not mutate
  project business data. Negative offsets, nonpositive limits, excessive page
  limits, and nonpositive preview budgets are rejected.

## Implementation and verification order

1. Commit the already verified schema 9 FTP slice independently.
2. Persist this contract and the exact next action in project checkpoints.
3. Add schema 10 plus migration tests from schema 9 and fresh databases.
4. Implement and exhaustively test the byte-stream RFC 854 parser.
5. Add bounded stream discovery, TCP reuse, records, source mappings, semantic
   relations, candidate joins, rerun replacement, and explicit failure states.
6. Add both CLI surfaces and deterministic bounded query tests.
7. Run Ruff, Windows Python 3.11 coverage, Python 3.9 regression, and build.
8. Run clean real acceptance twice and a separate constrained-budget project.
   Verify exact sample ranges, complete byte coverage, stable business counts,
   blob hashes, tool runs, integrity, foreign keys, and empty jobs.
9. Update `PROJECT_STATE.md`, `docs/ROADMAP.md`, README, and the ignored local
   handoff after each tested sub-slice and before the final commit.

Implementation must stop and update this contract before proceeding if real
sample evidence contradicts any byte range, role, parser, or idempotency rule.

All implementation and acceptance gates passed. Exact unit, migration,
Python 3.11/3.9, real-sample, bounded-budget, query, integrity, hash, and build
evidence is recorded in `PROJECT_STATE.md`.
