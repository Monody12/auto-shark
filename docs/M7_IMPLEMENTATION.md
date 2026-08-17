# M7 Implementation Contract

## Goal

M7 adds declared external analyzers and the optional constrained Linux node
without weakening the evidence model. Auto-Shark never executes captured
content: it executes only user-declared analyzer executables from validated
plugin manifests, passes carved artifact bytes as inert input data inside an
isolated job directory, and records every produced file by hash.

Implementation is checkpointed as 7A manifest/probe/local isolated runner,
7B the constrained SSH/SFTP Linux runner, and 7C the `ctf-stego-toolkit`
adapter once that project independently provides the required JSON and
output-directory contract. Each tested checkpoint updates
`PROJECT_STATE.md` before the next checkpoint begins.

## Plugin Manifest (`auto-shark.plugin/v1`)

- A manifest is one JSON file the user explicitly passes to Auto-Shark. It
  declares `name`, `version`, `executable`, `capabilities` (nonempty list),
  `arguments` (argument list containing `{input}` exactly where the input
  path belongs), `timeout_seconds` (1..3600), `stdout_limit_bytes` and
  `stderr_limit_bytes` (bounded), `max_output_files` (1..64),
  `max_output_file_bytes` and `max_output_total_bytes` (bounded), and an
  optional `result_file` name.
- Placeholders are limited to `{input}` and `{output_dir}`. No shell string,
  no environment expansion, no injection surface: invocation is always an
  argument list through the bounded process runner.
- Validation failures are explicit `ValueError` messages; nothing executes
  during validation or probing. Probing checks manifest validity and
  executable existence only.

## Isolated Local Run

- A run targets one persisted `artifact` whose Blob must exist, be complete,
  and hash-verify on disk. The Blob bytes are copied into
  `jobs/plugins/<run-id>/input/` under a sanitized suggested name.
- The analyzer runs with the argument list substituted with the absolute
  input/output paths, the declared timeout, and the declared stdout/stderr
  limits through `run_bounded`.
- Every file left in `output/` is recorded with relative path, byte length,
  and SHA-256 under the per-file, per-run file-count, and total-byte limits.
  Over-limit, unreadable, or excess files become explicit `plugin_output_skip`
  rows (`file-limit`, `file-byte-limit`, `total-byte-limit`, `unreadable`).
- A declared `result_file` is parsed as JSON when present, within a bounded
  size, and stored as normalized JSON detail; oversized or invalid results
  become explicit skips (`result-too-large`, `result-invalid-json`).
- Run status is `completed`, `failed` (nonzero exit or output-limit kill), or
  `timeout`. Stdout/stderr record byte counts, hashes, and truncation flags;
  raw text beyond the declared limits is never stored.
- Schema 1 `plugin_run` rows persist provenance (plugin identity, input
  artifact, job directory, status, timing); schema 15 adds the bounded detail,
  output, and skip tables plus the registered-manifest table. Plugin job
  directories under `jobs/plugins/` are durable runtime output, unlike the
  temporary extraction `jobs/` directories.
- Auto-Shark never executes, renders, imports, or unpacks an artifact or any
  produced file; interpretation of analyzer results stays with the human.

## CLI

- `plugin-probe <manifest>` prints `auto-shark.plugin-probe/v1` JSON and
  exits nonzero when the manifest is invalid or the executable is missing.
- `plugin-run <project> <manifest> --artifact <artifact-id>` executes one
  isolated run and prints `auto-shark.plugin-run/v1` JSON.

## Verification Gates

1. Manifest validation matrix and probe behavior.
2. Synthetic-project run tests with a controlled fake analyzer: completed,
   failed, timeout, output-count/file/total caps, declared-result parse and
   invalid/oversized results, missing artifact, blob-integrity rejection.
3. Schema 14-to-15 migration test; integrity and foreign-key checks.
4. Real smoke: register one local manifest, run it against the carved JPEG
   artifact of the multipart acceptance project, and verify recorded hashes
   against an independent hash of the produced files.
5. Ruff, full Windows Python 3.11 coverage, Python 3.9 regression, `uv
   build`, and wheel-content inspection before the 7A commit.

The SSH/SFTP Linux runner (7B) and the `ctf-stego-toolkit` adapter (7C) are
out of scope for 7A and require their own contracts: 7B must probe absolute
remote executables before any allowlisted job and enforce request/response
hash verification; 7C depends on that toolkit independently gaining the JSON
output and explicit output-directory interface recorded as an active risk.
