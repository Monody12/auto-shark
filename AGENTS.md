# Auto-Shark Repository Guidance

## Mandatory Session Start

Every agent or developer session must read these files completely, in order:

1. `AGENTS.md`
2. `PROJECT_STATE.md`
3. `docs/ROADMAP.md`
4. `PROJECT_HANDOFF.local.md` when it exists

Then inspect `git status --short --branch` and the latest commits before making
changes. Treat the checked-in files as the durable source of truth when chat
history or memory disagrees with them.

## Mandatory Checkpoint Updates

- Update `PROJECT_STATE.md` after every tested implementation slice and before
  ending a working session.
- Record completed work, exact verification commands/results, active risks,
  and the single next executable step. Do not use vague entries such as
  "continue implementation".
- Update `docs/ROADMAP.md` when milestone scope or status changes.
- Put machine-specific paths, tool versions, credentials guidance, local
  sample observations, and uncommitted handoff details in
  `PROJECT_HANDOFF.local.md`. Never put secrets in any project file.
- Keep public architecture and product decisions in `docs/`; do not leave
  important decisions only in chat.
- Before claiming a milestone complete, verify every exit criterion recorded
  in `docs/ROADMAP.md` and write the evidence to `PROJECT_STATE.md`.

## Scope

- This directory is the standalone `auto-shark` project. Do not modify sibling
  directories unless the user explicitly approves a cross-project change.
- Build an offline-first CTF packet-analysis workbench and automation tool.
- Windows is the primary controller and GUI platform. Linux is an optional
  constrained enhancement node.
- Analyze one offline PCAP/PCAPNG project at a time in v1. Live capture and
  batch challenge analysis are out of scope.
- The CLI core must support Python 3.9+. Development and the PySide6 GUI target
  Python 3.11.

## Product Invariants

- Use TShark as the primary protocol engine through structured subprocess
  output. PyShark must not be a required core dependency.
- Every conclusion must be traceable to original capture evidence: capture
  hash, frame or frame range, conversation, protocol message or transaction,
  byte source/range, transformation, detector, and tool run.
- Use bounded streaming and on-disk indexes. Never infer that decoded output
  fits in RAM from capture size alone.
- Never execute extracted scripts or binaries.
- External analyzers require declared capabilities, argument-list invocation,
  timeouts, stdout/stderr limits, artifact limits, and isolated job directories.
- Flag answers may be test oracles only. Never hard-code them into detectors or
  expose the answer file to an analysis run.
- Preserve raw evidence and transformation lineage even when decoded evidence
  produces a higher-confidence candidate.

## Development Conventions

- Use `uv` for Python and dependency management. Do not use direct `pip
  install` for the project environment.
- Keep source, documentation, lockfiles, and small sanitized fixtures in this
  repository. Keep virtual environments, caches, build output, live analysis
  projects, extracted artifacts, and large reports outside OneDrive.
- Set `UV_PROJECT_ENVIRONMENT` to a machine-local directory before `uv sync`.
- Capability-detect external tools rather than assuming they are on `PATH` or
  enforcing a version string alone.
- Use SQLite migrations and stable machine-readable schemas. Schema changes
  require tests and a recorded compatibility decision.
- Use parameterized SQL and subprocess argument lists; never concatenate shell
  commands or user-derived paths.
- Add focused tests with every behavioral change. Validate the core on Windows
  Python 3.11 and Linux Python 3.9.

## Local Resources

- Machine-specific sample and tool paths are recorded in
  `PROJECT_HANDOFF.local.md`; production code must discover them through
  configuration and probing.
- The former sibling `pyshark/` prototype remains read-only reference material
  in the parent personal repository. Do not migrate or modify it implicitly.

