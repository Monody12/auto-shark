# Auto-Shark

Auto-Shark is an offline-first CTF packet-analysis workbench. It combines a
reproducible CLI, a Windows investigation GUI, evidence-preserving automation,
and optional constrained Linux analyzers.

The project is under active implementation. The first supported workflow opens
one PCAP/PCAPNG capture, builds an on-disk index with TShark, ranks explainable
flag candidates, reconstructs HTTP/TCP/FTP/Telnet evidence, and exports an
offline report without executing captured content.

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

