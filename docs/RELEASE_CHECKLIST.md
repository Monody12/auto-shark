# v0.3.0 release checklist

Status legend: [x] verified with recorded evidence, [ ] pending execution.

## Code and acceptance

- [x] Focused SMTP/database/CLI/inventory/queue/reporting/GUI regression passes
      after explicit incomplete-DATA provenance was added: 74 passed.
- [x] Real DDCTF SMTP-only rerun recovers eight complete messages and one
      complete PNG attachment, with one explicit incomplete DATA at stream
      2007/frame 8280. Integrity, foreign keys, 135 Blob hashes, and empty jobs
      pass; FTP stream 2005 was not analyzed.
- [x] Ruff, compileall, and `git diff --check` pass on the release tree.
- [x] Full Windows Python 3.11.15 suite passes with real TShark 4.6.7:
      300 passed.
- [x] Full Windows Python 3.9.25 suite passes with real TShark 4.6.7:
      289 passed and one expected optional GUI skip.
- [x] Wheel and sdist build successfully; wheel contains `smtp.py`, GUI code,
      plugins, remote adapter, reporting, and all other runtime modules.

## Product and documentation

- [x] Schema 16 records SMTP messages, attachments, and explicit skip reasons.
- [x] `smtp-extract` uses bounded TCP reconstruction, preserves raw EML, maps
      MIME payloads back to exact stream/frame evidence, and never executes
      recovered content.
- [x] GUI new-project flow accepts an optional bounded legacy TLS RSA key for
      the current run without persisting its path or bytes.
- [x] README and user guide cover SMTP recovery, budgets, evidence, TLS limits,
      and the GUI key picker.
- [x] Version metadata is 0.3.0 with the existing Beta classifier.
- [ ] `PROJECT_STATE.md` and `docs/ROADMAP.md` contain final release evidence.

## Windows packages

- [x] `scripts/build_windows_release.ps1 -RequireInstaller` emits installer,
      stable-root portable ZIP, wheel, sdist, and `SHA256SUMS`.
- [x] Frozen CLI reports `auto-shark 0.3.0`; probe, `smtp-extract --help`,
      fixture analyze/report, and runtime adapter presence pass.
- [x] Frozen GUI starts under the offscreen Qt backend.
- [x] A v0.2.0-to-v0.3.0 installer upgrade removes a stale `_internal` marker,
      preserves a machine-local project, and the upgraded CLI can read it.
- [x] Silent uninstall removes the program directory while preserving projects.

## Published release

- [ ] Main commit and annotated `v0.3.0` tag are pushed.
- [ ] Tag-triggered GitHub Actions release workflow completes successfully.
- [ ] GitHub Release v0.3.0 exposes installer, portable ZIP, wheel, sdist, and
      `SHA256SUMS`.
- [ ] Every published asset is downloaded and independently verified against
      the published checksum manifest.
- [ ] Downloaded wheel and portable package pass version/content/probe and
      offscreen GUI checks.

## Clean-machine install test (run once before announcing)

1. On a fresh Windows 11 VM with Python 3.11 and Wireshark installed:
   `pipx install auto-shark[gui] --fork-suppress` (or
   `uv tool install --from . auto-shark[gui]` from the sdist).
2. Set `AUTO_SHARK_TSHARK` to the installed tshark.exe.
3. `auto-shark probe`, then `auto-shark analyze tests/fixtures/http-smoke.pcap
   --project %LOCALAPPDATA%\AutoShark\projects\smoke --with-bodies --scan`.
4. `auto-shark gui` - open the smoke project, run analysis from the menu,
   export a bundle.
5. Verify the exported `manifest.json` hashes match the files.

## Known residual risks

- The historical WebShell runtime project has two missing blob paths on the
  development machine; they are recorded, not rewritten, and are not required
  by any stable result.
- Interactive GUI responsiveness was validated offscreen plus scripted
  rendering; hands-on desktop acceptance remains a separate clean-machine run.
- Legacy RSA TLS support is intentionally limited to compatible server-key
  handshakes. ECDHE, TLS 1.3, and TLS key-log input are unsupported.
