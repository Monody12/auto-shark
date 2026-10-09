# Auto-Shark

Auto-Shark is an offline-first CTF packet-analysis workbench: a reproducible
CLI, a Windows investigation GUI, evidence-preserving automation, bounded
external analyzers, and optional constrained Linux jobs.

One PCAP/PCAPNG capture becomes an on-disk project with a full evidence
lineage: TShark-structured protocol indexing, precise HTTP pairing, body
extraction with budgets, TCP/FTP/Telnet reconstruction, explainable candidate
ranking, CTF behavior detectors (unknown flag-like values, SQL injection,
WebShell timelines, Struts/OGNL command execution), a persistent manual-review queue, and deterministic
offline report/HTML/evidence export. Captured content is never executed.

## Quick start

Requirements: Python 3.11 (3.9 for the CLI core), [uv](https://docs.astral.sh/uv/),
and TShark 4.x (Wireshark). Set `AUTO_SHARK_TSHARK` or pass `--tshark`.

```powershell
$env:UV_PROJECT_ENVIRONMENT = "$env:LOCALAPPDATA\AutoShark\venvs\dev"
uv sync --all-groups --extra gui      # gui extra is optional
uv run auto-shark probe
```

Analyze a capture end to end (metadata, bodies, transforms, static files):

```powershell
uv run auto-shark analyze capture.pcapng `
  --project "$env:LOCALAPPDATA\AutoShark\projects\case1.auto-shark" `
  --with-bodies --scan
uv run auto-shark triage   "$env:LOCALAPPDATA\AutoShark\projects\case1.auto-shark"
uv run auto-shark detect   "$env:LOCALAPPDATA\AutoShark\projects\case1.auto-shark"
uv run auto-shark index-summary "$env:LOCALAPPDATA\AutoShark\projects\case1.auto-shark"
uv run auto-shark tcp-text "$env:LOCALAPPDATA\AutoShark\projects\case1.auto-shark"
uv run auto-shark tftp-extract "$env:LOCALAPPDATA\AutoShark\projects\case1.auto-shark"
uv run auto-shark smtp-extract "$env:LOCALAPPDATA\AutoShark\projects\case1.auto-shark"
uv run auto-shark dns-triage "$env:LOCALAPPDATA\AutoShark\projects\case1.auto-shark"
uv run auto-shark icmp-triage "$env:LOCALAPPDATA\AutoShark\projects\case1.auto-shark"
uv run auto-shark tcp-urgent "$env:LOCALAPPDATA\AutoShark\projects\case1.auto-shark"
uv run auto-shark usb-hid "$env:LOCALAPPDATA\AutoShark\projects\case1.auto-shark"
uv run auto-shark export   "$env:LOCALAPPDATA\AutoShark\projects\case1.auto-shark" `
  "$env:LOCALAPPDATA\AutoShark\exports\case1"
```

For a challenge capture that provides a server private key and uses a
compatible legacy RSA key exchange, pass the key explicitly so decrypted HTTP
re-enters the same body, scan, and detector pipeline:

```powershell
uv run auto-shark analyze legacy-tls.pcap `
  --project "$env:LOCALAPPDATA\AutoShark\projects\legacy-tls.auto-shark" `
  --tls-rsa-key challenge-server.pem --with-bodies --scan
uv run auto-shark detect `
  "$env:LOCALAPPDATA\AutoShark\projects\legacy-tls.auto-shark"
```

The key is bounded to 1 MiB and read only. Auto-Shark records its SHA-256 and
byte length, but does not copy the key or persist its local path. A server RSA
key cannot decrypt ECDHE or TLS 1.3 sessions.

Or do the same from the Windows GUI (`--extra gui` required):

```powershell
uv run auto-shark gui
```

The GUI is the primary human surface and follows the standard CTF solving
funnel: open (or drag-and-drop) a capture and the full analysis starts
automatically — no separate menu step. The landing page is a **solve wizard**:
protocol hierarchy, recognized challenge types (HTTP upload, directory
brute-force, WebShell, SQL injection, DNS tunneling, USB HID, Telnet/FTP
credentials, VoIP, SNMP) with evidence and a double-click jump to the right
page, ranked flag candidates (double-click to copy), and an honest five-step
checklist when nothing fires. A per-challenge flag format (regex) can be
entered on the wizard and re-scans the stored evidence in seconds; the same
pattern is available to the CLI as `--flag-format` / `flag-format`. The Files
page lists every carved/exported artifact, and HTTP bodies, TCP streams, and
Telnet dialogues have hex+ASCII content viewers.

TShark is located automatically (settings → `AUTO_SHARK_TSHARK` → PATH →
Program Files → registry → `AUTO_SHARK_TSHARK_DIRS`), preferring the newest
installed version; auto-discovered copies below 4.x are rejected. Individual
analysis stages that cannot run are skipped with a recorded reason instead of
aborting the pipeline, and stage failures are summarized once at the end.

TLS decryption accepts either a challenge-provided RSA private key
(`--tls-rsa-key`, legacy key exchange only) or an NSS keylog file
(`--tls-keylog`, covers ECDHE/TLS 1.3). A keylog named `ssl_keys.log`
(next to the capture) is picked up automatically. Global search
(`Search everywhere` on the wizard, or `auto-shark grep <project> <needle>`)
scans every stored body/stream/file at once with raw, hex, and base64
alignment variants. ICMP stages cover both the TTL side channel and
data-payload concatenation (`icmp-data-stream` evidence); SNMP
variable-binding strings are concatenated into scannable evidence
(`snmp-triage`). The transform chain decodes hex/base64 and now also
gzip/zlib layers, so base64-compressed WebShell payloads unravel
automatically. The built-in flag
pattern understands `flag{…}`, `key: …`, `key=…`, and English
`the key is …` phrasing, in addition to any challenge-specific regex.

For Windows users, the GitHub Release provides two application packages:

- `AutoShark-Windows-x64-Setup.exe` is the Windows installer. The wizard lets
  you choose a per-user install (`%LOCALAPPDATA%\Programs\Auto-Shark`) or a
  machine-wide install (`C:\Program Files\Auto-Shark`, requires Administrator).
  Silent flags are `/CURRENTUSER` and `/ALLUSERS`. The application identity is
  stable, so a newer installer upgrades the existing copy instead of creating a
  version-named directory. Analysis projects stay under
  `%LOCALAPPDATA%\AutoShark\projects` in both modes.
- `AutoShark-Windows-x64-Portable.zip` is the no-install package. Its archive
  root is always `AutoShark`, so extracting a new release into the same parent
  does not create a new version directory. Close the application before
  replacing the old portable directory.

Both packages embed Python 3.11 and PySide6. Wireshark/TShark remains a
separate dependency because of its GPL distribution and platform-specific
installation requirements.

The GUI opens or creates projects, runs the staged analysis pipeline with
progress and between-stage cancellation, and provides bounded pages for
overview, HTTP, streams, Telnet, candidates/findings, the WebShell timeline,
the WebShell timeline, and bundle export. The new-project dialog
accepts an optional legacy TLS RSA private key for the initial analysis run;
the path and key bytes are not saved in GUI settings or project metadata.

The GUI selects Simplified Chinese automatically for `zh-*` Windows/Linux
locales and uses English as the fallback for all other or unknown locales. Set
`AUTO_SHARK_LANGUAGE=zh-CN` or `AUTO_SHARK_LANGUAGE=en-US` only when testing or
reproducing a support report.

## What each stage records

- `analyze --with-bodies --scan`: HTTP metadata pairing, bounded body
  extraction, URL/Base64/hex transform lineage, static file carving. Add
  `--tls-rsa-key` only for a challenge-provided key and compatible legacy RSA
  TLS traffic.
- `triage`: known-format and authentication-field candidates with exact byte
  ranges and versioned score signals.
- `detect`: unknown flag-like candidates, multi-signal SQL-injection events,
  static PHP WebShell operations, and Struts/OGNL command execution from
  URL-form field names with correlated response evidence.
- `index-summary`: capture/conversation inventory, coverage states, multipart
  findings, and the persistent manual-analysis queue.
- `tcp-text`: reconstructs bounded generic TCP `data` streams, reuses the
  shared candidate scanner, and records exact source frames; recognized HTTP,
  TLS, SSH, FTP, and Telnet streams are left to their protocol analyzers.
- `tftp-extract`: discovers RRQ and WRQ negotiations, follows negotiated UDP
  routes, reconstructs duplicate-aware 16-bit block sequences across wrap,
  and only promotes complete, gap-free, conflict-free transfers to artifacts.
- `smtp-extract`: discovers SMTP DATA transactions, reconstructs bounded TCP
  directions, preserves raw EML evidence, decodes MIME attachments, and records
  exact source-stream ranges and contributing frames. Incomplete DATA and
  exhausted message/attachment budgets remain explicit; recovered files are
  never executed.
- `dns-triage`: bounded hex/Base32/Base64URL label grouping and preview;
  only uniquely reconstructed PNG data with valid chunk CRCs is promoted to
  an artifact, while ambiguous streams remain manual-review evidence.
- `icmp-triage`: correlates IPv4 echo requests with TShark's explicit response
  references and flags printable, varying TTL guesses only when replies are
  selective; incomplete captures remain partial oracle evidence, not flags.
- `tcp-urgent`: reconstructs non-zero TCP urgent-pointer values by stream and
  direction, preserving frame provenance and promoting flag-shaped text.
- `usb-hid`: inventories USB report lengths per endpoint, decodes conservative
  Boot Keyboard key-down edges, recognizes supported absolute-coordinate
  report series, and flags captures where input devices should be correlated
  by frame or timestamp.
- SNMP inventory rows receive a dedicated manual-review hint for community,
  OID, and OctetString/variable-binding inspection.
- `voip-extract`: bounded G.711 PCMU/PCMA RTP-to-WAV artifacts with SIP/SDP,
  telephone-event, sequence-gap, and FSK follow-up hints.
- `report` / `export`: deterministic `auto-shark.report/v1` JSON and a
  self-contained offline HTML + manifest + bounded evidence directory.

## Query surfaces

`transactions`, `streams`, `telnet-dialogues`, `summary`, `manual-queue`,
`findings`, `timeline --detector <name>`, `notes`, and `report` emit bounded, paginated,
versioned JSON that never inlines blob bytes or machine-local paths.

## External analyzers (plugins)

Declared analyzers run in isolated job directories with argument-list
invocation, declared timeouts and output caps, and SHA-256-hashed outputs:

```powershell
uv run auto-shark plugin-probe manifest.json
uv run auto-shark plugin-run <project> manifest.json --artifact <artifact-id>
```

A generic working-directory adapter
(`src/auto_shark/assets/cwd_adapter.py`) wraps tools that print terminal
prose instead of JSON — including `ctf-stego-toolkit` — by preserving their
terminal output verbatim as hashed evidence files. See
[plugins/examples/README.md](plugins/examples/README.md).

Linux nodes run the same manifests through constrained SSH/SFTP jobs with
request/result hash verification:

```powershell
uv run auto-shark remote-probe --host user@node --path /usr/bin/python3
uv run auto-shark remote-probe --host user@node --port 22 --identity $env:USERPROFILE\.ssh\id_ed25519 --path /usr/bin/python3 --path /usr/bin/binwalk
uv run auto-shark remote-run <project> manifest.json --artifact <id> --host user@node
```

## Product boundaries

- Offline captures only in v1; no live capture or multi-challenge batch mode.
- TShark is the protocol engine. PyShark is not a core dependency.
- Every conclusion traces back to capture bytes and tool-run provenance.
- Extracted scripts, binaries, and decoded payloads are never executed;
  archives are never unpacked.
- Flag answers are test oracles only and are never hard-coded into detectors.
- Terminal output of external tools is preserved as evidence, never parsed
  into structured conclusions.

## Development

```powershell
$env:UV_PROJECT_ENVIRONMENT = "$env:LOCALAPPDATA\AutoShark\venvs\dev"
uv sync --all-groups --extra gui
uv run ruff check .
$env:AUTO_SHARK_TSHARK = "C:\path\to\tshark.exe"
uv run pytest --cov=auto_shark
```

CI installs real TShark on Windows Python 3.11 and Linux Python 3.9, runs the
full suite, and smoke-analyzes the committed fixture capture. Widget tests
run offscreen and skip cleanly without the `gui` extra.

## Documentation

- [User guide](docs/USER_GUIDE.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Roadmap](docs/ROADMAP.md)
- [Release checklist](docs/RELEASE_CHECKLIST.md)
- [Recovery protocol](docs/RECOVERY.md)
- [Acceptance captures](docs/ACCEPTANCE_SAMPLES.md)
- [Challenge corpus strategy](docs/CORPUS_STRATEGY.md)
- [Project state](PROJECT_STATE.md) — the canonical tested checkpoint

## License

MIT. TShark/Wireshark is a separate GPLv2 program invoked as an external
tool; PySide6 is an optional extra. See [LICENSE](LICENSE) and
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
