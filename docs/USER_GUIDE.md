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
uv run auto-shark index-ftp "$projects\case1.auto-shark"
uv run auto-shark scan "$projects\case1.auto-shark" --with-files
uv run auto-shark triage   "$projects\case1.auto-shark"
uv run auto-shark detect   "$projects\case1.auto-shark"
uv run auto-shark index-summary "$projects\case1.auto-shark"
uv run auto-shark tcp-text "$projects\case1.auto-shark"
```

`tcp-text` handles captures where an unrecognized application sends printable
data directly over TCP, including one-character-per-packet challenges. It only
selects conversation profiles whose labels are generic TCP/`data`, then reuses
the normal TCP sequence reconstruction and candidate evidence mapping. Defaults
are 32 streams, 16 MiB per stream, and 64 MiB total; skipped or failed streams
remain explicit. Recognized HTTP, TLS, SSH, FTP, and Telnet conversations are
not selected by this generic pass.

For TFTP captures, reconstruct both RRQ downloads and WRQ uploads after the
initial project is created:

```powershell
uv run auto-shark tftp-extract "$projects\case1.auto-shark"
uv run auto-shark scan "$projects\case1.auto-shark" --with-files
```

The stage follows the server's negotiated UDP port instead of relying only on
Wireshark object export, which can miss uploaded DATA frames. It deduplicates
blocks, detects conflicting and missing data, handles the 16-bit block number
wrap used by files larger than 32 MiB, and records server errors and exhausted
budgets as evidence. Only a complete transfer becomes an artifact. Transferred
packages and scripts are never executed.

For DNS-heavy captures, run the encoded-label pass. It groups suspicious
hex/Base32/Base64URL labels by route and base domain, records a bounded decoded
preview and duplicate statistics, and rebuilds the manual queue:

```powershell
uv run auto-shark dns-triage "$projects\case1.auto-shark"
```

The detector treats capture order as a heuristic. Only a unique PNG whose
structure and chunk CRCs validate is automatically exported; other decoded
streams remain evidence with framing and ordering advice.

For ICMP challenges, inspect echo request TTL values and explicit reply
associations as a bounded side channel:

```powershell
uv run auto-shark icmp-triage "$projects\case1.auto-shark"
```

The analyzer only promotes a TTL oracle when a route has enough requests,
several printable TTL candidates, and both multiple replies and multiple
unanswered probes. A reply marks an accepted guess for the captured step; it
does not prove any prefix or suffix missing from the capture.

For side channels in TCP header fields, inspect non-zero urgent pointers. The
command groups values by TCP stream and direction, decodes printable bytes in
capture order, and records both the raw field values and contributing frames:

```powershell
uv run auto-shark tcp-urgent "$projects\case1.auto-shark"
```

For USB captures, inventory HID-like endpoints before assuming that every
8-byte report is a keyboard. The analyzer checks the Boot Keyboard reserved
byte, release reports, and known key-code ratio; it separately recognizes the
supported 10-byte absolute-coordinate/pressure pattern and recommends
cross-device time correlation when both appear:

```powershell
uv run auto-shark usb-hid "$projects\case1.auto-shark"
```

SNMP is currently a review-oriented slice: protocol inventory recognizes it
and the manual queue points to community strings, OIDs, request/response pairs,
and OctetString values. It does not claim automatic MIB interpretation or
answer extraction.

Encrypted TLS that has not been decrypted receives a dedicated manual queue
item. When a challenge supplies a server private key and the handshake uses a
compatible legacy RSA key exchange, rerun the initial workflow with the key:

```powershell
uv run auto-shark analyze legacy-tls.pcap `
  --project "$projects\legacy-tls.auto-shark" `
  --tls-rsa-key challenge-server.pem --with-bodies --scan
uv run auto-shark detect "$projects\legacy-tls.auto-shark"
```

The CLI accepts a regular file up to 1 MiB. It uses the key only as a TShark
RSA Keys UAT input, records its SHA-256 and byte length, and redacts its local
path from persisted tool arguments. The key bytes are never copied into the
project. Supply the same option to `extract-body` when reopening the project
for a one-frame extraction. A server RSA key does not decrypt ECDHE or TLS 1.3
traffic; those sessions require appropriate key-log material, which Auto-Shark
does not currently accept.

For Telnet captures, index the directional dialogue before triage. Client
input may arrive one character per packet, use bare CR line endings, and be
echoed by the server, so packet-by-packet string concatenation is misleading:

```powershell
uv run auto-shark index-telnet "$projects\case1.auto-shark"
uv run auto-shark telnet-dialogues "$projects\case1.auto-shark" --stream 0
uv run auto-shark triage "$projects\case1.auto-shark"
```

The Telnet index preserves CR/CRLF/CR-NUL boundaries, prompt/input/echo
relations, Tab/backspace controls, and source frames. Triage scans the current
directional reconstructions for flag candidates.

For SIP/RTP captures, run the bounded VoIP pass after the inventory. It writes
supported G.711 PCMU/PCMA directions as WAV artifacts and records the source
frame range, SSRC, codec, sequence gaps, and transformation in the project:

```powershell
uv run auto-shark voip-extract "$projects\case1.auto-shark"
uv run auto-shark report "$projects\case1.auto-shark" > voip-report.json
```

The pass deliberately does not pretend to decode every RTP codec. Unsupported
payload types and RTP telephone-event packets remain visible in the report and
manual queue. If the WAV contains modem tones, try a declared FSK tool such as
`minimodem` at 300 baud, then keep its terminal output as analyzer evidence.

Every stage is idempotent: rerunning it appends provenance without changing
business results. Each stage also accepts explicit byte/count budgets (see
`auto-shark <command> --help`); when a budget is hit the skipped items are
recorded, never silently dropped.

Alternatively launch the GUI. `File > Open capture…` picks a .pcap/.pcapng
directly, creates (or reopens) a machine-local project under
`%LOCALAPPDATA%\AutoShark\projects`, and runs the staged analysis
automatically. The GUI correlates FTP transfers before static-file carving, so
downloaded archives and executables reach the artifact review queue without a
separate command. Configure TShark or the optional Linux node once in
`Edit > Settings…` (the dialog probes both and persists the paths):

```powershell
uv run auto-shark gui            # requires the optional gui extra
```

The GUI detects the operating-system language at startup. Chinese locales
(`zh-*`) use Simplified Chinese; every other locale falls back to English so
the interface is never partially translated. For packaging tests or support
reproduction, the automatic choice can be overridden without changing the
system locale:

```powershell
$env:AUTO_SHARK_LANGUAGE = "zh-CN"  # or "en-US"
uv run auto-shark gui
```

On Linux the same rule uses `LC_ALL`, `LANG`, `LANGUAGE`, and the active Python
locale. The override is optional and is not required for normal use.

Projects cannot live in synced directories such as OneDrive; the GUI
defaults to the machine-local path above and explains the rule if a synced
location is chosen.

## 3. Reading the results

- `summary` — protocols, conversations (TCP/UDP), endpoints, coverage states.
- `transactions` — paired HTTP requests/responses with body/task states.
- `streams` / `telnet-dialogues` — reconstructed TCP directions and RFC 854
  dialogue records with prompt/input/echo relations.
- `tcp-text` — bounded generic TCP-data reconstruction plus shared flag triage,
  with selected/skipped stream counts and exact contributing frames.
- `findings` — candidates with rank, signals, and evidence links; detector
  findings with severity.
- `timeline` — one detector's deduplicated behavior timeline. It defaults to
  `static-webshell-activity`; use
  `--detector struts-ognl-command-injection` for OGNL command execution.
- `manual-queue` — everything that needs a human, ranked by priority.
- `tftp-extract` — bounded RRQ/WRQ reconstruction with direction, frame range,
  block gaps/conflicts, wrap handling, file hashes, and server-error records.
- `voip-extract` — bounded G.711 RTP-to-WAV reconstruction with frame/SSRC
  provenance and explicit DTMF/FSK follow-up hints.
- `dns-triage` — suspicious encoded DNS-label groups, bounded previews,
  retransmission statistics, and strictly validated recovered PNG artifacts.
- `icmp-triage` — printable TTL guess sequences, explicit echo reply mapping,
  accepted-value previews, and partial-capture warnings.
- `tcp-urgent` — per-stream/per-direction TCP urgent-pointer text, source
  frames, and high-confidence flag-shaped candidates.
- `usb-hid` — endpoint report-length inventory, conservative keyboard events,
  absolute-coordinate ranges, pressure ranges, and multi-device correlation
  hints.

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

## 8. Windows release packages

The release page publishes an installer and a portable ZIP. The installer is
per-user and uses the fixed directory `%LOCALAPPDATA%\Programs\Auto-Shark`;
installing a later release over it upgrades the same directory and preserves
analysis projects. The portable ZIP always contains a top-level `AutoShark`
directory. Extract it beside the previous copy and replace that directory
after closing the application.

Neither package includes Wireshark/TShark. Configure the executable from
`Edit > Settings` or set `AUTO_SHARK_TSHARK` before starting the CLI. The
packaging script is reproducible on a Windows build host:

```powershell
uv sync --all-groups --extra gui
choco install innosetup
./scripts/build_windows_release.ps1 -RequireInstaller
```

Omit `-RequireInstaller` when only the portable package is needed on a machine
without Inno Setup.
