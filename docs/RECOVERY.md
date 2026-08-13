# Recovery Protocol

The repository must be recoverable from any PC and any new Agent session
without relying on hidden conversation state.

## Start a new session

1. Allow OneDrive to finish synchronizing the repository.
2. Read `AGENTS.md`, `PROJECT_STATE.md`, `docs/ROADMAP.md`, and the local handoff.
3. Run `git status --short --branch` and `git log -5 --oneline --decorate`.
4. Compare the active milestone and next step with the current files/tests.
5. Set `UV_PROJECT_ENVIRONMENT` to a machine-local path and run the verification
   commands recorded in `PROJECT_STATE.md` before changing behavior.

Suggested resume prompt:

> Read AGENTS.md, PROJECT_STATE.md, docs/ROADMAP.md, and
> PROJECT_HANDOFF.local.md completely. Inspect Git state and rerun the recorded
> checkpoint verification. Continue from the exact next executable step. Keep
> PROJECT_STATE.md current after every tested slice and preserve all unrelated
> user changes.

## Finish or checkpoint a session

Update `PROJECT_STATE.md` with:

- milestone and status;
- behavior completed, with relevant files;
- exact commands run and meaningful result counts;
- incomplete or unverified areas;
- decisions and risks discovered;
- one concrete next action, including the intended module/test.

Update `docs/ROADMAP.md` when an exit criterion changes state. Put local paths,
installed tool versions, sample hashes, and machine-only observations in
`PROJECT_HANDOFF.local.md`. Never store passwords, API keys, SSH private keys,
or live remote credentials.

Commit a coherent verified checkpoint before changing PCs. Do not commit live
analysis databases, extracted artifacts, environments, caches, or secrets.

