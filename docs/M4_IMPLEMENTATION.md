# M4 Implementation Contract

## Goal

M4 turns the current evidence index into bounded, explainable CTF behavior
detection. It adds conservative unknown flag-like candidates, HTTP SQL-injection
behavior reconstruction, and a static WebShell operation timeline. It does not
execute decoded code, open carved artifacts, or read answer files.

Implementation is checkpointed as 4A unknown-candidate detection, 4B SQL
behavior reconstruction, and 4C WebShell timeline plus bounded queries. Each
tested sub-slice updates `PROJECT_STATE.md` before the next behavior is added.

## Schema 13

- `detector_run` records one M4 invocation, the capture, rule version, bounded
  policy, terminal status, processed/skipped input counts, result counts, and
  timestamps.
- `detector_skip` records every input omitted because of a row, byte, field,
  transaction, preview, or result limit. Missing or incomplete evidence is
  explicit and is never treated as a clean negative result.
- `behavior_event` records one stable per-transaction operation with request and
  optional response frames, detector/version, event kind, normalized target,
  semantic key, confidence, status, bounded detail JSON, and an optional
  `duplicate_of` link to the earliest equal semantic operation in the capture.
- `behavior_event_evidence` links operation, target, payload, response, and
  baseline evidence roles without copying payload bytes.
- `behavior_event_run` links stable events to every run that reproduced them.

Existing `candidate`, `candidate_signal`, `finding`, `finding_evidence`,
`finding_run`, and manual-queue tables remain authoritative for conclusions and
review. Detector reruns update automatic facts and provenance only; they never
overwrite notes, review marks, manual-task state, or artifact review state.

## 4A - Unknown flag-like candidates

The bounded scanner adds exact range evidence for two conservative shapes:

- an unknown printable prefix followed by a balanced `{value}` token; and
- a long standalone token with mixed character classes, only when length,
  boundary, and diversity rules all pass.

Known `flag|ctf|key|answer{...}` matches keep their existing score and identity.
Unknown brace tokens rank below known formats. Unstructured long tokens rank
below structured sensitive fields and enter the manual queue only above the
documented threshold. Placeholders, repeated single-class strings, URLs,
ordinary prose, protocol headers, and values already represented by a stronger
candidate are excluded. Every scan is bounded by evidence count, bytes per
evidence, total bytes, matches per evidence, and total candidates.

## 4B - SQL-injection behavior

HTTP query parameters and complete URL-form fields are inspected as structured
values. Static signals include quote/comment boundaries, boolean expressions,
UNION/SELECT structure, metadata-table references, stacked statements, and
time-delay functions. A keyword alone is insufficient.

Requests are grouped by method, normalized path, and parameter name. When a
clean comparison request exists, response status and bounded body/declared
length differences become additional evidence. Without a comparison request,
the event is retained as `partial` and confidence is capped. One stable finding
summarizes related probes for an endpoint/parameter; individual request events
remain ordered and traceable. The detector does not send traffic or replay a
request.

## 4C - Static WebShell timeline

The first rules recognize common PHP WebShell wrappers and classify decoded
actions by static API shapes, including system information, directory listing,
file read/write/delete/rename, directory creation, command execution, and
database actions. Parameter values are resolved only from already persisted
bounded transforms. Payload bytes stay in the blob store; detail JSON contains
only capped previews, sizes, hashes, and evidence IDs.

Every selected HTTP transaction yields at most one primary operation event.
Chronology follows request frame order. Equal event kind plus normalized target
and stable action shape links later events to the earliest event as duplicates;
the original transactions and evidence are not deleted. A bounded query can
return either the concise deduplicated timeline with repeat counts or every
event.

The local WebShell acceptance capture must produce 19 ordered target POST
events: one system-information action, fifteen directory listings, one file
write, and two file reads. Normalized semantic deduplication must produce eight
groups while preserving all request/response frame links. Frame 1068 is the
file write to `D:\wamp64\www\upload\6666.jpg`; frames 1364 and 1721 are file
reads for `hello.zip` and `1.php` respectively.

## CLI and JSON

- `auto-shark detect <project>` runs all enabled M4 detectors under independent
  row/byte/result budgets and then refreshes automatic manual-queue signals.
- `auto-shark findings <project>` emits `auto-shark.findings/v1` with candidate,
  finding, and evidence-link pagination; it never inlines blob bytes.
- `auto-shark timeline <project>` emits `auto-shark.timeline/v1`, defaults to a
  deduplicated view, and supports event kind, status, request-frame range,
  duplicate inclusion, offset, and limit filters.

Unknown schema major versions are rejected. Detail and preview bytes have
independent caps, and all JSON ordering is deterministic.

## Additional public samples

Additional captures are used only when they add behavior or protocol coverage
missing from the five local samples. Each local-only sample records its public
source URL, retrieval date, SHA-256, license or usage statement when available,
and the exact acceptance behavior. Captures, extracted files, and published
answers are never committed or made available to production detectors.

Downloads must be direct public challenge/sample artifacts from an identifiable
source. No executable from a sample is run. Archives are not unpacked unless a
separate, explicit safety decision authorizes a bounded fixture-import process.

## Verification gates

1. Fresh schema 13 creation and schema 12-to-13 migration; integrity and
   foreign-key checks.
2. Unknown-token boundary, chunk overlap, false-positive, byte/result budget,
   exact evidence range, ranking, and rerun tests.
3. SQL query/form parsing, multi-signal classification, clean-baseline
   comparison, missing/truncated response, deduplication, and limit tests.
4. WebShell wrapper/action classification, target resolution, chronological
   ordering, semantic duplicate links, missing fields, binary payload, and
   preview-budget tests. Decoded code is inspected only as bytes/text.
5. Stable findings/timeline JSON pagination and manual-state preservation tests.
6. Run M4 twice on all five local acceptance projects. Verify the WebShell
   19-event/eight-group contract, no regression to existing candidate ranks,
   stable business rows, integrity, foreign keys, blob rehashes, completed tool
   runs, and empty job directories.
7. Add at least one source-recorded public SQL-injection capture if no local
   capture exercises 4B end to end; keep it machine-local.
8. Run Ruff, Windows Python 3.11 coverage, Python 3.9 regression, `uv build`,
   and wheel-content inspection before the M4 commit.
