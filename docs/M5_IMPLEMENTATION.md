# M5 Implementation Contract

## Goal

M5 turns the indexed evidence and detector results into a durable investigation
record and a portable offline report. It adds explicit human review marks,
stable notes, deterministic JSON, self-contained HTML, and an optional bounded
evidence directory. It never executes exported content, opens archive members,
or embeds arbitrary Blob bytes in JSON or HTML.

Implementation is checkpointed as 5A investigation state, 5B report read model
and JSON, and 5C HTML/evidence export plus reopen determinism. Each tested
checkpoint updates `PROJECT_STATE.md` before the next checkpoint begins.

## Schema 14 And Human State

- Existing `review_mark` rows remain the authoritative per-subject mark. States
  remain `unreviewed`, `needs_review`, `excluded`, and `key_evidence`.
- Schema 14 adds `investigation_note` with a stable public ID and capture scope.
  On first M5 access, legacy `note` rows are copied without deletion and receive
  deterministic SHA-256 public IDs derived from their persisted locator; new
  notes are written only through the scoped table.
- Reviewable subject kinds are initially `candidate`, `finding`, `artifact`,
  `behavior-event`, `manual-task`, and `evidence`. A mutation is accepted only
  when that public subject exists in the current capture.
- Notes are append-only through create operations and editable by stable note
  ID. Empty notes, invalid states, cross-capture subjects, and notes above the
  configured UTF-8 byte limit are rejected. No automatic process edits review
  marks or note bodies.

## Report JSON

`auto-shark.report/v1` contains capture identity and size, schema version,
protocol coverage, result counts, candidates, findings, deduplicated behavior
events, artifacts, manual tasks, human marks and notes, evidence locators, and
bounded tool/detector provenance. It does not include the machine-local project
path, original capture path, current time, SQLite integer keys, or Blob bytes.

Every repeated collection has a count, returned count, independent limit, and
explicit truncation flag. Detail JSON, note bodies, and other free text have
separate UTF-8 byte limits. Ordering is fixed by public IDs or documented
chronology. JSON serialization uses sorted keys, UTF-8, and one trailing
newline so reopening an unchanged project produces byte-identical output.

## Offline HTML And Evidence Export

- HTML is a single UTF-8 file with inline CSS and embedded escaped report JSON.
  It uses no network resources, scripts, images, fonts, or Blob data.
- A bundle is written only to a new or empty destination directory. Files are
  staged before publication so a failed export does not claim success.
- `report.json`, `report.html`, and `manifest.json` are always produced.
  Manifest entries contain relative paths, byte lengths, and SHA-256 hashes.
- Optional evidence export copies exact referenced evidence ranges into an
  `evidence/` directory under independent item, per-item byte, and total byte
  limits. Names are generated from evidence IDs and detected extensions, never
  from untrusted paths. Missing, incomplete, out-of-range, or over-budget data
  becomes an explicit manifest skip and is never silently omitted.
- Exported files are inert evidence. Auto-Shark does not render, unpack,
  decrypt, import, or execute them.

## CLI

- `review-mark <project> <subject-kind> <subject-id> --state ...` upserts one
  human mark after current-capture subject validation.
- `note-add <project> <subject-kind> <subject-id> --body ...` creates one note.
- `note-update <project> <note-id> --body ...` edits one current-capture note.
- `notes <project>` returns bounded `auto-shark.notes/v1` JSON with subject
  filters and pagination.
- `report <project>` emits deterministic `auto-shark.report/v1` JSON.
- `export <project> <output-directory>` creates the offline bundle and accepts
  explicit report/evidence limits.

Unknown schema major versions are rejected. Invalid limits fail before any
output file or database mutation is created.

## Verification Gates

1. Fresh schema 14 creation and schema 13-to-14 migration; integrity and
   foreign-key checks.
2. Review validation/upsert, note create/update, legacy note ID backfill,
   cross-capture rejection, UTF-8 limits, and automatic-rerun preservation.
3. Deterministic report ordering, category/text budgets, no absolute paths,
   no Blob bytes, empty/partial/failed states, and stable schema tests.
4. Self-contained HTML escaping, offline-resource checks, atomic new/empty
   destination behavior, exact evidence ranges, hash manifest, missing Blob,
   path traversal, item/byte limits, and no archive processing tests.
5. Reopen one unchanged project and export to two fresh directories; JSON,
   HTML, evidence files, and manifest must be byte-identical.
6. Run all five acceptance projects through bounded report collection. Verify
   existing manual state, notes, candidates, findings, and WebShell timeline;
   then run integrity, foreign-key, Blob/hash, tool-run, and empty-jobs checks.
7. Run Ruff, Windows Python 3.11 coverage, Python 3.9 regression, `uv build`,
   and wheel-content inspection before the M5 commit.
