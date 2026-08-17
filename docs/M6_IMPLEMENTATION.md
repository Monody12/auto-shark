# M6 Implementation Contract

## Goal

M6 delivers the Windows-first PySide6 investigation UI on top of the existing
bounded read models. The GUI adds no new analysis logic: every displayed value
comes from the already-tested query, report, investigation, and export
surfaces. The CLI core stays importable and functional without PySide6 on
Python 3.9.

Implementation is checkpointed as 6A headless services and CLI entry, 6B
application shell with project open/create, threaded analysis, and core views,
then 6C remaining views plus export and real-sample smoke. Each tested
checkpoint updates `PROJECT_STATE.md` before the next checkpoint begins.

## Dependency And Import Rules

- PySide6 stays an optional extra (`pip install auto-shark[gui]`) with the
  existing `python_version >= '3.11'` marker. Nothing in the installed core
  requires it.
- `src/auto_shark/gui/__init__.py` exposes only availability helpers.
- `src/auto_shark/gui/services.py` imports no Qt module. It is a headless,
  Python 3.9-compatible facade returning plain dictionaries and stage
  callables so it is unit-testable without any GUI toolkit.
- `auto_shark.gui` imports PySide6 lazily inside `run_gui`; the CLI gains a
  `gui` subcommand that prints an actionable install hint and exits with code 2
  when the extra is missing.

## Services Layer

- `ProjectServices(project_path)` binds one project and exposes:
  - `info()` via `inspect_project`.
  - `overview()`, `summary()`, `transactions()`, `streams()`,
    `telnet_dialogues()`, `findings()`, `timeline()`, `manual_queue()`, and
    `notes()` returning the parsed JSON payloads of the existing bounded
    queries with their documented defaults.
  - `set_review_mark()`, `add_note()`, `update_note()`,
    `update_manual_task_state()`, and `export_bundle_to()` wrapping the
    existing mutation surfaces and returning their JSON payloads.
- `resolve_tshark(explicit)` wraps `find_tshark` plus `Settings` discovery.
- `analysis_stages(tshark, capture=None)` returns an ordered list of named
  stages. A new project runs `analyze --with-bodies --scan` first; every
  project then runs `scan --with-files`, `triage`, `detect`, and
  `index-summary` with the CLI defaults. Stage callables return the stage's
  machine-readable summary object.
- Stage failures stop the pipeline run, are reported with the stage name and
  error text, and never roll back the durable per-stage results that already
  succeeded.

## Threading And Cancellation

- Bounded SQLite queries run synchronously on the UI thread; the analysis
  pipeline and bundle export run in a `QThread` worker.
- The worker emits `stage_started`, `stage_finished` (with the stage summary
  JSON), `stage_failed`, and finished/cancelled signals. The dialog renders
  the per-stage summary counts as each stage completes.
- Cancel is cooperative between stages: once requested, no further stage
  starts, the in-flight bounded stage is allowed to finish and persist, and
  the run reports `cancelled` with the completed stage names. The UI never
  kills a subprocess or database transaction.

## Views

- Navigation pages: Overview, HTTP, Streams, Telnet, Findings, Timeline,
  Manual queue, Notes, Export.
- Every page implements explicit states: no-project placeholder, empty
  result, populated table, and truncated banner (`showing X of Y`) driven by
  the payload count/limit/truncation fields rather than guesses.
- Paginated pages reuse the offset/limit parameters of the underlying query.
- Candidate/finding/task selection renders signal and evidence-link detail
  from the query payloads; nothing re-reads the database directly.
- Manual queue state changes, review marks, and note edits use the same
  validation and error surfaces as the CLI and refresh the affected page.
- The Export page writes the offline bundle through `export_bundle` and shows
  the manifest counts and skip reasons.

## Security And Display Rules

- The GUI never executes, renders, imports, or unpacks captured content or
  artifacts, and offers no shell-open action for them.
- Detail text is previewed from bounded query payloads only; Blob bytes are
  not read by any view.
- Absolute machine paths shown in the status bar come from `ProjectInfo` and
  are never written into exported artifacts.

## Verification Gates

1. Services unit tests without PySide6: payload pass-through, stage order,
   TShark resolution, and mutation forwarding against a synthetic project.
2. CLI `gui` subcommand: helpful failure without the extra, argument
   acceptance, lazy import isolation on Python 3.9.
3. Widget tests with `QT_QPA_PLATFORM=offscreen`, skipped when PySide6 is
   absent: window construction, project open, per-page populated and empty
   states, truncation banners, pagination, review-mark round trip, and worker
   stage/cancel behavior with stubbed stages.
4. Real-sample smoke on Windows Python 3.11: open each acceptance project,
   render every page, run one staged analysis refresh, and export one bundle
   to a temporary directory.
5. Ruff, full Windows Python 3.11 coverage, Python 3.9 regression (GUI tests
   skipped), `uv build`, and wheel-content inspection before the M6 commit.
