# M3 Slice 3 Summary and Manual Queue Implementation Contract

## Scope and invariants

This slice adds bounded capture inventory, analysis coverage, multipart
correlation, general findings, and a persistent manual-analysis queue. It
reuses existing HTTP, TCP, FTP, Telnet, evidence, candidate, file-carve, and
artifact rows. It never copies payload bytes into inventory or multipart rows,
never opens an artifact, and never treats a protocol label as proof that an
analyzer completed successfully.

Implementation is checkpointed as 3A inventory, 3B multipart/findings, and 3C
queue/query/CLI. Schema 11 defines the slice tables. Schema 12 is an append-only
compatibility repair for runtime projects that materialized the tested 3A
Schema 11 before the 3B/3C tables were added; fresh databases receive the same
final table set through both migrations.

## Verified acceptance facts

- Telnet: one TCP conversation, 310 payload bytes. Current Auto-Shark output is
  one complete dialogue with 44 records. A TShark malformed annotation on an
  individual frame must not override the complete byte parser result.
- HTTP login: 24 TCP and 12 UDP conversations, 29 HTTP frames, one orphan
  response, and one TCP reconstruction with four conflicting bytes. OICQ and
  TLS are observed protocols without current analyzers.
- FTP: 11 TCP and 79 UDP conversations, five FTP control messages and one
  FTP-DATA message. The complete 164-byte RAR artifact remains unopened and
  must enter the manual queue.
- Multipart: eight TCP and 14 UDP conversations, eight HTTP frames. Frame 233
  declares an `image/jpeg` part associated with the carved JPEG. Frame 260 is
  HTTP 500 while its complete body contains a bounded success semantic; this
  must create exact range evidence and a contradiction finding.
- WebShell: 14 TCP and four UDP conversations, 48 HTTP frames, 19 target POST
  transactions, one unmatched request, and ZIP/JPEG artifacts requiring
  review. The decoded WebShell operation timeline remains M4 scope.

No adjacent answer file is available to any production command or detector.
No capture artifact may be listed, opened, unpacked, decrypted, rendered, or
executed during acceptance.

## Schema 11

### Capture inventory

- `capture_inventory_run` stores the stable public run ID, capture, TShark tool
  run, policy JSON, terminal status, processed/skipped counts, and timestamps.
- `protocol_observation` stores one current stable row per capture/protocol
  label: frame count and first/last frame. A run link identifies the inventory
  that last produced it.
- `conversation_profile` stores one stable TCP or UDP conversation per capture,
  transport stream, endpoints, first/last frame and time, frame/captured/wire/
  payload byte totals, protocol-label JSON, and the TCP initial-SYN role when
  proven. UDP never receives inferred client/server roles.
- `conversation_profile_run` records every inventory run that observed a stable
  conversation profile without duplicating the profile business row.
- `inventory_skip` aggregates excluded frame, conversation, or protocol-label
  work by scope and reason. Every configured row/label/conversation limit and
  missing-field case is explicit.
- `analysis_coverage` stores the current status for a protocol observation or
  conversation. Allowed states are `complete`, `partial`, `not-run`,
  `unavailable`, `failed`, and `budget-limited`. Its detail JSON records the
  capability, latest successful run, current reconstruction/analyzer state, and
  skips used to derive the status.

TShark inventory reads bounded structured fields one line at a time:
`frame.protocols`, frame number/time/length, IPv4/IPv6 endpoints, TCP/UDP
stream/ports and payload length, and TCP SYN/ACK. It does not request payload
hex. TCP initiator/responder is recorded only from an initial SYN with ACK
unset. Missing optional fields remain explicit; endpoint or stream omissions
do not cause guessed conversations.

Coverage precedence is: unavailable capability, failed analyzer run,
budget-limited metadata or business state, partial/conflicting/truncated state,
complete current analyzer result, then not-run. A successful Auto-Shark parser
may establish complete coverage even when TShark labels one frame malformed.

### Multipart and findings

- `multipart_part` stores a stable part ID, HTTP protocol message, inventory
  tool run, ordinal, field name, filename, declared media type, status, and
  detail JSON. It never stores part bytes.
- `multipart_part_artifact` links a part to an artifact and optional carve with
  role `matched`, `type-mismatch`, or `unresolved` plus detail JSON.
- Existing `finding` and `finding_evidence` tables hold stable general
  findings. Schema 11 adds `finding_run` to associate idempotent findings with
  the index-summary tool run that produced them.

A part is linked only when one HTTP message has exactly one compatible part
and one carved artifact. Multiple parts, multiple carves, missing fields, or
ambiguous ownership produce `unresolved`; no filename, order, or type guess is
used. A unique declared/detected media-type difference creates a
`declared-actual-type-mismatch` finding.

Complete HTTP response bodies receive a bounded ASCII/UTF-8 static success-word
scan. A 5xx response with a bounded success semantic creates exact byte-range
evidence and an `http-status-body-contradiction` finding. Missing or truncated
bodies are recorded as not-run or partial coverage and never scanned as if
complete.

### Persistent manual queue

- `manual_queue_run` stores rule version, policy JSON, created/updated/skipped
  counts, terminal status, and timestamps.
- `manual_task` stores a stable task ID and subject, task kind, automatic
  suggested priority, manual state, and timestamps. States are `open`,
  `in-progress`, `resolved`, and `dismissed`.
- `manual_task_signal` stores the producing queue run, rule/version, score, and
  bounded detail JSON. A rebuild replaces only automatic signals and suggested
  priority for affected subjects.
- `manual_task_evidence` links zero or more evidence rows to a task with an
  explicit role.

Stable subject identity deduplicates multiple signals for one candidate,
artifact, finding, protocol observation, conversation, or transaction.
Automatic rebuilds never overwrite `manual_task.state`, `review_mark`, `note`,
or `artifact.review_state`.

Initial rules and scores are:

- rank-100 known-format candidate: 100;
- analyzer failure or HTTP status/body contradiction: 90;
- TCP conflict/gap or partial/truncated protocol result: 85;
- unreviewed archive/executable artifact or sensitive-field candidate: 80;
- trailing data and unmatched/orphan HTTP transaction: 65 through 75;
- unsupported high-volume protocol/conversation: lower priority and bounded by
  a configured top-N.

Routine background DNS/SSDP does not create one task per flow. It remains in
the summary and may only contribute to a bounded aggregate protocol task.

## CLI and JSON contracts

- `auto-shark index-summary <project> --tshark <path>` builds inventory,
  coverage, multipart/findings, and the automatic queue with independent
  limits for frames, labels, conversations, parts, scans, tasks, signals, and
  evidence links.
- `auto-shark summary <project>` emits `auto-shark.summary/v1` with deterministic
  pagination and no inline Blob bytes.
- `auto-shark manual-queue <project>` emits `auto-shark.manual-queue/v1` and
  supports state, kind, minimum priority, subject kind/ID, offset, and limit.
- `auto-shark manual-task <project> <task-id> --state <state>` changes only the
  manual queue state and update timestamp.

Every response includes applied limits, total counts, returned counts, and
truncation indicators. Detail JSON and previews have independent byte limits.
Unknown public schema major versions are rejected by the existing project
open path.

## Verification gates

1. Fresh schema 11 creation and schema 10-to-11 migration; integrity and
   foreign-key checks.
2. IPv4/IPv6, TCP/UDP, initial SYN, no-SYN, missing fields, row/label/
   conversation budgets, subprocess failure, and rerun stability tests.
3. Coverage precedence tests proving labels do not override parser state and
   unavailable/failed/budget/partial states remain distinct.
4. Multipart unique, multiple-part, multiple-carve, missing-field,
   type-mismatch, complete-body contradiction, and truncated-body tests.
5. Queue rule, subject deduplication, idempotent rebuild, manual-state
   preservation, filtering, pagination, and all auxiliary budget tests.
6. Run `index-summary`, `summary`, and `manual-queue` twice against each of the
   five clean acceptance projects. Verify the conversation/protocol counts and
   exact key frames above, stable business counts, integrity, foreign keys,
   independent Blob rehash, completed tool runs, and empty job directories.
7. Run Ruff, Windows CPython 3.11 coverage, CPython 3.9 regression, `uv build`,
   and wheel-content inspection before the slice commit.
