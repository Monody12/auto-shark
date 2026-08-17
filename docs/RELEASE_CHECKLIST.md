# v1 release checklist

Status legend: [x] verified with recorded evidence, [ ] pending execution.

## Code and tests

- [x] Ruff clean on Windows Python 3.11.
- [x] Full suite green on Windows Python 3.11 with coverage.
- [x] Full suite green on Linux/Python 3.9 semantics (widget tests skip).
- [x] `uv build` produces sdist + wheel; wheel contains every runtime module
      including `plugins.py`, `remote.py`, `reporting.py`, `exporting.py`,
      `gui/*`, and `assets/cwd_adapter.py`.
- [x] CI installs real TShark on both matrix runners and smoke-analyzes the
      committed `tests/fixtures/http-smoke.pcap` through
      `analyze --with-bodies --scan` + `report`.
- [x] Malformed/short/empty captures fail bounded and rerun-stable.
- [x] Interrupted `running` body tasks recover on the next extraction run.

## Acceptance evidence

- [x] Five private acceptance captures (Telnet, HTTP form, FTP, multipart,
      WebShell) run the full inventory/detector/report/export workflow with
      stable counts, byte-identical repeated reports, and identical
      two-directory exports.
- [x] One public SQL-injection teaching capture with recorded provenance and
      a stable partial event/finding.
- [x] Real plugin run against the frame-233 JPEG artifact with independent
      hash verification.
- [x] Real `ctf-stego-toolkit` run through the working-directory adapter;
      terminal output preserved as hashed evidence files.
- [ ] Real Linux-node `remote-probe`/`remote-run` validation (requires
      user-provided node credentials; fake-transport tests cover the logic).

## Packaging and docs

- [x] LICENSE (MIT) and THIRD_PARTY_NOTICES.md present.
- [x] README quick start, boundaries, and development instructions current.
- [x] User guide covers setup, full analysis, queries, review, export,
      plugins/remote, and the safety model.
- [x] Example plugin manifests documented in `plugins/examples/README.md`.
- [x] `scripts/auto-shark-gui.cmd` launcher for Windows desktops.
- [x] Version 0.1.0 with Beta classifier.

## Clean-machine install test (run once before announcing)

1. On a fresh Windows 11 VM with Python 3.11 and Wireshark installed:
   `pipx install auto-shark[gui] --fork-suppress` (or
   `uv tool install --from . auto-shark[gui]` from the sdist).
2. Set `AUTO_SHARK_TSHARK` to the installed tshark.exe.
3. `auto-shark probe`, then `auto-shark analyze tests/fixtures/http-smoke.pcap
   --project %LOCALAPPDATA%\AutoShark\projects\smoke --with-bodies --scan`.
4. `auto-shark gui` — open the smoke project, run analysis from the menu,
   export a bundle.
5. Verify the exported `manifest.json` hashes match the files.

## Known residual risks

- The historical WebShell runtime project has two missing blob paths on the
  development machine; they are recorded, not rewritten, and are not required
  by any stable result.
- Interactive GUI responsiveness was validated offscreen plus scripted
  rendering; hands-on desktop acceptance happens in the clean-machine test.
