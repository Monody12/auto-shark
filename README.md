# Auto-Shark

Auto-Shark is an offline-first CTF packet-analysis workbench. It combines a
reproducible CLI, a Windows investigation GUI, evidence-preserving automation,
and optional constrained Linux analyzers.

The project is under active implementation. The first supported workflow opens
one PCAP/PCAPNG capture, builds an on-disk index with TShark, ranks explainable
flag candidates, reconstructs HTTP/TCP/FTP/Telnet evidence, and exports an
offline report without executing captured content.

The current runnable checkpoint can probe TShark, create/reopen a machine-local
project, and persist/precisely pair HTTP-over-TCP metadata:

```powershell
uv run auto-shark probe --tshark C:\path\to\tshark.exe
uv run auto-shark analyze capture.pcapng `
  --project "$env:LOCALAPPDATA\AutoShark\projects\capture.auto-shark" `
  --tshark C:\path\to\tshark.exe
```

Body extraction, decoding, candidate ranking, and reports are still active M2+
work; consult `PROJECT_STATE.md` rather than assuming they are implemented.

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
broader unknown-format triage are still active M2 work.

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
