# Architecture

## Processing layers

```text
capture + capability probe
        |
TShark structured adapters
        |
SQLite evidence index + content-addressed blobs
        |
protocol reconstruction -> bounded transforms -> detectors -> candidates
        |
CLI / PySide6 investigation UI / JSON / offline HTML / evidence export
```

The four ownership layers are parsing adapters, unified evidence storage,
detectors/transforms/plugins, and user/report surfaces. Protocol adapters may
record facts but do not decide flags. Detectors consume evidence and create
explainable findings and candidates.

## Analysis project

Each capture opens in a machine-local directory:

```text
project.auto-shark/
├── project.sqlite
├── blobs/sha256/aa/<digest>
├── jobs/<job-id>/
├── logs/
└── exports/
```

SQLite uses WAL mode, foreign keys, explicit migrations, and one writer queue.
Arbitrary-size decoded packet output and artifact bytes are streamed into the
blob store, not stored as SQLite BLOB columns.

## Core records

- `capture`: source name, size, SHA-256, format, time bounds.
- `tool_run`: exact tool/version, arguments with sensitive data redacted,
  timing, exit state, stderr truncation, and capability snapshot.
- `frame`, `conversation`, `protocol_message`, `transaction`: indexed protocol
  facts and request/response or control/data relationships.
- `blob`: content hash, length, media/magic description, storage path, and
  completeness.
- `evidence`: original byte or structured-field locator with capture lineage.
- `transform`: parent evidence, named/versioned operation, bounded parameters,
  output evidence, and status.
- `finding` and `candidate`: detector conclusions linked through many-to-many
  evidence tables; investigation marks and notes remain independent user state.
- `artifact`, `plugin_run`, `remote_job`: static exports and constrained tool
  execution provenance.

Database integer keys are internal. Public identifiers are SHA-256 hashes of
versioned, canonical JSON locators. A candidate ID is based on candidate kind
and normalized value, allowing new supporting evidence without changing it.

## TShark contract

TShark is launched with an argument list, `shell=False`, bounded stderr, a
timeout, and a controlled environment. Metadata is read line by line from
structured fields. Body/object extraction streams to files. Natural-language
`-V` or Follow Stream output is diagnostic only and never the primary parser.

The first capability profile requires or probes:

- protocols: TCP, HTTP, FTP, FTP-DATA, Telnet, MIME multipart;
- HTTP request/response association and body fields;
- TCP stream, payload, segment and reassembled-data fields;
- FTP command, response and data setup/command fields;
- Telnet data;
- export-object support for HTTP and FTP-DATA when available.

Missing required core fields block analysis with an actionable diagnostic.
Missing protocol-specific fields disable only the affected analyzer. TShark
4.6.7 on Windows is the first verified profile; Linux 4.4 latest patch is the
first planned CI profile, with 4.2 maintained as best-effort compatibility.

## Search and transform pipeline

Search inputs include raw payload bytes, printable runs, protocol fields,
reassembled content, extracted files, URL-decoded values, Base64/Base64URL,
hex-derived text, and bounded archive metadata. Streaming scanners retain an
overlap at chunk boundaries.

Every transformation records the exact parent evidence, transform name and
version, parameters, output hash/length, depth, status, and truncation. Default
recursive depth is two. Size, expansion ratio, branch count, and total decoded
byte budgets are enforced per analysis. Original evidence is never replaced.

## Plugins and remote jobs

An in-process plugin or external adapter declares an API version, input types,
entry point, platform, tools, network policy, timeout, output limits, and
artifact limits. External commands receive an isolated job directory and may
not construct arbitrary shell commands.

Remote jobs reuse the adapter contract via constrained SSH/SFTP. The controller
uploads an input and request JSON, invokes an allowlisted adapter with absolute
probed executable paths, and downloads a result JSON plus hash-verified files.
Credentials live only in the user-local credential/configuration store.

The image adapter result schema is `auto-shark.adapter-result/v1` and contains
status, input hash, tool/version, findings, candidates, artifacts, warnings,
errors, limits, and truncation. Human-readable CLI prose is not parsed.

## User surfaces

CLI commands are `analyze`, `search`, `findings`, `export`, `plugins probe`,
`remote probe`, and `gui`. The launcher opens the GUI only when dependencies and
a usable display are available; otherwise it prints an explicit CLI fallback.

The GUI centers on project overview/triage, paired HTTP transactions, protocol
messages, search, findings/candidates, extracted files, evidence lineage,
investigation marks/notes, tool jobs, and export. TCP stream blobs remain a
secondary diagnostic view.

