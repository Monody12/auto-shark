# Auto-Shark

Auto-Shark is an offline-first CTF packet-analysis workbench. It combines a
reproducible CLI, a Windows investigation GUI, evidence-preserving automation,
and optional constrained Linux analyzers.

The project is under active implementation. The first supported workflow opens
one PCAP/PCAPNG capture, builds an on-disk index with TShark, ranks explainable
flag candidates, reconstructs HTTP/TCP/FTP/Telnet evidence, and exports an
offline report without executing captured content.

The current runnable checkpoint can probe TShark, create/reopen a machine-local
project, persist and precisely pair HTTP-over-TCP metadata, extract bounded
bodies, reconstruct TCP directions, apply bounded transforms, query indexed
transactions/streams, rank explainable triage candidates, and carve static file
evidence without executing or unpacking it:

```powershell
uv run auto-shark probe --tshark C:\path\to\tshark.exe
uv run auto-shark analyze capture.pcapng `
  --project "$env:LOCALAPPDATA\AutoShark\projects\capture.auto-shark" `
  --tshark C:\path\to\tshark.exe
```

Reports and protocol-specific M3 adapters remain future work; consult
`PROJECT_STATE.md` for the exact tested checkpoint.

One indexed HTTP body can currently be extracted with a hard decoded-byte cap:

```powershell
uv run auto-shark extract-body `
  "$env:LOCALAPPDATA\AutoShark\projects\capture.auto-shark" 1068 `
  --tshark C:\path\to\tshark.exe --max-bytes 16777216
```

The body is stored by SHA-256 outside SQLite; the command records evidence and
tool provenance. Extracted evidence can then be scanned with bounded transforms:

```powershell
uv run auto-shark scan `
  "$env:LOCALAPPDATA\AutoShark\projects\capture.auto-shark"
```

The scanner currently handles raw known-format flags and complete URL forms,
then one conservative Base64/Base64URL/hex layer. Automatic body selection and
scanning can run as one command:

```powershell
uv run auto-shark analyze capture.pcapng `
  --project "$env:LOCALAPPDATA\AutoShark\projects\capture.auto-shark" `
  --tshark C:\path\to\tshark.exe --uri /upload/1.php `
  --with-bodies --scan --max-body-total 67108864
```

Per-message task status is persisted, including explicit budget skips.

Indexed transactions and current reconstructed stream directions have stable,
bounded JSON query surfaces that never inline blob bytes:

```powershell
uv run auto-shark transactions `
  "$env:LOCALAPPDATA\AutoShark\projects\capture.auto-shark" `
  --uri /upload/1.php --offset 0 --limit 100

uv run auto-shark streams `
  "$env:LOCALAPPDATA\AutoShark\projects\capture.auto-shark"
```

Current body, transform, carved artifact, and TCP reconstruction evidence can
then be triaged under explicit byte/evidence/candidate budgets:

```powershell
uv run auto-shark triage `
  "$env:LOCALAPPDATA\AutoShark\projects\capture.auto-shark" `
  --max-evidence-bytes 67108864 --max-total-bytes 268435456
```

Triage records every completed, truncated, skipped, limited, or failed input.
Known-format ranges retain exact byte provenance; structured authentication
fields carry versioned score signals rather than answer-specific rules.

FTP control and FTP-DATA streams can be explicitly correlated and statically
exported under metadata, transfer, index, and output budgets:

```powershell
uv run auto-shark index-ftp `
  "$env:LOCALAPPDATA\AutoShark\projects\capture.auto-shark" `
  --tshark C:\path\to\tshark.exe `
  --max-transfer-bytes 268435456 --max-total-bytes 536870912
```

The FTP adapter uses TShark's setup/command frame references and the existing
bounded TCP reconstruction engine. Only a complete transfer direction becomes
exact `ftp-data` evidence and an unreviewed artifact. Archives are classified
by fixed magic bytes only; their contents are not listed, opened, decrypted, or
unpacked.

Telnet streams can be indexed as directional byte-accurate dialogues and then
queried without inlining full reconstruction blobs:

```powershell
uv run auto-shark index-telnet `
  "$env:LOCALAPPDATA\AutoShark\projects\capture.auto-shark" `
  --tshark C:\path\to\tshark.exe `
  --max-records 100000 --max-total-bytes 536870912

uv run auto-shark telnet-dialogues `
  "$env:LOCALAPPDATA\AutoShark\projects\capture.auto-shark" `
  --stream 0 --max-records 1000 --max-preview-bytes 256
```

The Telnet layer parses RFC 854 commands across frame boundaries from current
TCP reconstruction bytes, preserves binary/control ranges, and links prompts,
inputs, exact echoes, source frames, and overlapping candidates. Query previews
use reversible escapes and independent byte budgets; they are not the stored
evidence contract.

One bidirectional TCP stream can be indexed and reconstructed with explicit
segment and output budgets:

```powershell
uv run auto-shark reconstruct-stream `
  "$env:LOCALAPPDATA\AutoShark\projects\capture.auto-shark" 0 `
  --tshark C:\path\to\tshark.exe `
  --max-index-bytes 536870912 --max-direction-bytes 268435456
```

Directions are reconstructed independently by TCP sequence. Exact
retransmissions retain duplicate provenance without duplicating output;
conflicting overlaps and missing ranges remain explicit database records.
Captured bytes are never executed.

Static file carving is an explicit bounded operation. Ordinary `scan` does not
silently add its cost; use either command below:

```powershell
uv run auto-shark carve `
  "$env:LOCALAPPDATA\AutoShark\projects\capture.auto-shark" `
  --max-scan-bytes 67108864 --max-artifact-bytes 67108864

uv run auto-shark scan `
  "$env:LOCALAPPDATA\AutoShark\projects\capture.auto-shark" --with-files
```

Validated files, signature-only artifacts, prefixes, and trailing ranges retain
exact parent evidence. Archives, compressed data, images, and executables are
not opened, decrypted, unpacked, rendered, or executed by the carving layer.

## Product boundaries

- Offline captures only in v1; no live capture or multi-challenge batch mode.
- TShark is the protocol engine. Python PyShark is not a core dependency.
- Every finding retains a path back to capture bytes and tool-run provenance.
- Extracted scripts, binaries, and decoded payloads are never executed.
- Common URL, Base64, Base64URL, and hex transforms are bounded and explainable.
- Images may be submitted to a declared image-analysis adapter. Other files
  enter a manual-review queue in v1.

## Development status

Read [PROJECT_STATE.md](PROJECT_STATE.md) for the current tested checkpoint and
[docs/ROADMAP.md](docs/ROADMAP.md) for milestone exit criteria. New sessions
must follow the recovery procedure in [AGENTS.md](AGENTS.md).

## Development environment

The core supports Python 3.9+. Windows development and the future PySide6 GUI
use Python 3.11. Keep the environment outside OneDrive:

```powershell
$env:UV_PROJECT_ENVIRONMENT = "$env:LOCALAPPDATA\AutoShark\venvs\dev"
uv sync --all-groups
uv run auto-shark --help
uv run pytest
```

Runtime projects and extracted evidence must also use a machine-local location,
for example `%LOCALAPPDATA%\AutoShark\projects`.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Roadmap](docs/ROADMAP.md)
- [Recovery protocol](docs/RECOVERY.md)
- [Acceptance captures](docs/ACCEPTANCE_SAMPLES.md)
