# M2 Slice 6 Implementation Contract

Status: complete and verified as of 2026-08-13, Asia/Shanghai.

This slice completes the remaining M2 query and triage surfaces without
duplicating stored payloads or weakening evidence provenance.

## Stable query contracts

- `transactions` emits `auto-shark.transactions/v1` JSON with stable ordering
  by request frame and transaction ID, bounded `offset`/`limit`, total/count,
  optional exact URI filter, request/response summaries, and evidence/task
  status counts. It does not inline body bytes.
- `streams` emits `auto-shark.streams/v1` JSON with stable ordering by TCP
  stream index and direction, bounded `offset`/`limit`, segment/reconstruction
  counts, status, byte budgets, duplicate/conflict/gap counts, current evidence
  ID, blob hash/length, and frame range. It does not expose obsolete
  reconstruction evidence as current.
- Query commands do not write project business data after applying known
  append-only migrations and SQLite connection pragmas. Invalid negative
  offsets, nonpositive limits, and excessive limits are rejected. Default and
  maximum page sizes are explicit.

## Triage contract

- `triage` scans only current eligible evidence: HTTP bodies, transform outputs,
  carved artifact bytes, and evidence referenced by current TCP
  reconstructions. Historical TCP evidence, match evidence, form raw slices,
  file prefix/trailing slices, and incomplete artifact carves are not rescanned
  as independent whole inputs.
- Evidence coordinates stay in their native parent space. HTTP/form ranges are
  body-relative, TCP ranges are reconstruction-output-relative, and artifact
  scans read the artifact blob at offset zero while retaining the carved range
  evidence that links it back to its parent blob.
- Byte scans are fixed-window with overlap and enforce per-evidence, total-byte,
  evidence-count, printable-value, and candidate-count budgets. Every skipped or
  truncated input is reported in the summary; no selected input disappears.
- Known `flag|ctf|key|answer{...}` matches remain highest confidence and create
  exact range evidence. For TCP streams, output ranges are mapped through
  `tcp_reconstruction_source` to the contributing frame or frame range.
- Broader rules are conservative and explainable. Structured decoded fields
  named `password`, `passwd`, `passphrase`, `secret`, `token`, `api_key`, or
  `key` may become `sensitive-field` candidates when their bounded printable
  value is nonempty and non-placeholder. Other nonempty printable fields in
  the same authentication form may become lower-ranked `context-field`
  candidates so the ordered event is inspectable. Field role, length, and
  hex/Base64-like shape contribute named score components; a password-role
  contribution must keep the password above email and captcha context.
- Generic printable tokens are not promoted merely for being long or random.
  This avoids flooding candidates with payload and archive data. Broader
  unknown-token heuristics remain M4 work unless backed by a structural context.
- Candidate values are normalized without hard-coded answers. Candidate IDs
  remain stable by kind/value. `candidate_signal` records detector/version,
  signal name, numeric contribution, detail JSON, and supporting evidence.
- Repeated triage is idempotent for candidates, evidence links, and signals.
  Higher scores may update a candidate but history/provenance is not discarded.
- A scan record is stable per evidence, detector/version, and configured
  limits. A rerun with the same limits updates its status/counts; a different
  limit policy gets a distinct stable scan ID so a bounded result is not
  mistaken for a full scan.

## Acceptance evidence

- Telnet stream 0 must yield the known-format candidate from client frame 41;
  candidate evidence must reference the exact TCP-stream byte range and frame
  41 through reconstruction source mapping. The verified reconstruction range
  is `[82,120)`, length 38, with frame 41 as its sole primary source.
- HTTP form request frame 20 must yield ordered field candidates where the
  `password` value ranks above `email` and `captcha` without reading an answer
  file. Its evidence must retain the URL-form transform chain to frame 20. The
  verified 65-byte body has ordered body-relative raw ranges `email [6,10)`,
  `password [20,52)`, and `captcha [61,65)`; the password is a 32-byte
  printable hexadecimal-shaped value.
- Transaction and stream pages must be deterministic across repeat calls and
  project reopen. Page bounds, empty results, exact URI filtering, conflict
  visibility, and current-evidence selection require focused tests.
- Ruff, Python 3.11 coverage, Python 3.9 tests, real-sample repeated runs,
  foreign-key checks, stable row counts, and empty `jobs` directories must pass
  before updating `PROJECT_STATE.md` or marking M2 complete.

## Implementation order

1. Finish schema 8 and deterministic transaction/stream query surfaces.
2. Add a single current-evidence selector and bounded streaming scanners.
3. Persist exact known-format matches and TCP contributing-frame mappings.
4. Add structured field role candidates and versioned score signals.
5. Expose `triage` limits and summaries through the CLI.
6. Pass focused unit/migration tests, then clean real-sample repeat runs and
   the full Python 3.11/3.9 verification gates.

All six steps and acceptance gates passed. Exact commands, counts, hashes,
scores, frame/range mappings, and clean runtime-project checks are recorded in
`PROJECT_STATE.md`.
