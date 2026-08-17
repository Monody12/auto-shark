# Auto-Shark user guide

This guide walks through the complete analysis workflow on one offline
PCAP/PCAPNG capture. All examples use PowerShell on Windows; the same
commands work on Linux with `uv run auto-shark ...`.

## 1. Setup

- Python 3.11 for the GUI, 3.9+ for the CLI core.
- [uv](https://docs.astral.sh/uv/) for environment management.
- TShark 4.x from a Wireshark installation. Point Auto-Shark at it once:

```powershell
$env:AUTO_SHARK_TSHARK = "C:\Program Files\Wireshark\tshark.exe"
uv run auto-shark probe
```

`probe` prints the version and each capability (HTTP, TCP reassembly, FTP,
FTP-DATA, Telnet, multipart). Analysis refuses to run with an unusable TShark
rather than guessing.

Projects live in a machine-local directory (never inside a synced folder):

```powershell
$projects = "$env:LOCALAPPDATA\AutoShark\projects"
```

## 2. Full analysis

```powershell
uv run auto-shark analyze capture.pcapng `
  --project "$projects\case1.auto-shark" --with-bodies --scan
uv run auto-shark triage   "$projects\case1.auto-shark"
uv run auto-shark detect   "$projects\case1.auto-shark"
uv run auto-shark index-summary "$projects\case1.auto-shark"
```

Every stage is idempotent: rerunning it appends provenance without changing
business results. Each stage also accepts explicit byte/count budgets (see
`auto-shark <command> --help`); when a budget is hit the skipped items are
recorded, never silently dropped.

Alternatively launch the GUI and use `File > New project from capture…`:

```powershell
uv run auto-shark gui            # requires the optional gui extra
```

## 3. Reading the results

- `summary` — protocols, conversations (TCP/UDP), endpoints, coverage states.
- `transactions` — paired HTTP requests/responses with body/task states.
- `streams` / `telnet-dialogues` — reconstructed TCP directions and RFC 854
  dialogue records with prompt/input/echo relations.
- `findings` — candidates with rank, signals, and evidence links; detector
  findings with severity.
- `timeline` — the deduplicated WebShell operation timeline.
- `manual-queue` — everything that needs a human, ranked by priority.

All queries are paginated (`--offset/--limit`) and never inline blob bytes.

## 4. Human review

```powershell
uv run auto-shark manual-task "$projects\case1.auto-shark" <task-id> --state resolved
uv run auto-shark review-mark "$projects\case1.auto-shark" candidate <candidate-id> --state key_evidence
uv run auto-shark note-add    "$projects\case1.auto-shark" candidate <candidate-id> --body "password reused across logins"
uv run auto-shark notes       "$projects\case1.auto-shark"
```

Manual state survives every automatic rebuild; automation never overwrites
your marks, notes, or queue states.

## 5. Reports and export

```powershell
uv run auto-shark report "$projects\case1.auto-shark" > report.json
uv run auto-shark export "$projects\case1.auto-shark" "$env:LOCALAPPDATA\AutoShark\exports\case1"
```

The bundle contains `report.json`, a self-contained offline `report.html`,
`manifest.json` with per-file SHA-256 hashes, and an `evidence/` directory of
bounded exact ranges. Missing or incomplete blobs become explicit manifest
skips. Repeated exports of an unchanged project are byte-identical.

## 6. External analyzers

Write a manifest (template in
[plugins/examples/README.md](../plugins/examples/README.md)) declaring the
executable, capabilities, argument list with `{input}`/`{output_dir}`
placeholders, and limits. Then:

```powershell
uv run auto-shark plugin-probe manifest.json
uv run auto-shark plugin-run "$projects\case1.auto-shark" manifest.json --artifact <artifact-id>
```

Outputs are hashed into the project database; terminal prose is preserved as
`stdout.txt`/`stderr.txt` evidence files, never parsed. On a Linux node the
same manifest runs through `remote-probe`/`remote-run` with request/result
hash verification.

## 7. Safety model

- Captured content, extracted files, and archive members are never executed,
  unpacked, decrypted, or rendered by Auto-Shark.
- Only analyzers you explicitly declare in manifests are executed, in
  isolated job directories, with timeouts and output caps.
- Flag answers are used only as after-the-fact test oracles, never inside
  detectors.
