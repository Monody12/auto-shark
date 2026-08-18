# v0.2.0 release checklist

Status legend: [x] verified with recorded evidence, [ ] pending execution.

## Code and tests

- [x] Ruff clean on Windows Python 3.11.
- [x] Full suite green on Windows Python 3.11.15 with real TShark 4.6.7:
      274 passed.
- [x] Full suite green on Windows Python 3.9.25 minimum-version semantics:
      264 passed and one optional GUI-widget skip.
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
- [x] Linux-node capability probe and adapter setup over the configured SSH
      connection. A full toolkit run was bounded and recorded as `exit 124`
      after producing output; lightweight analyzer validation remains useful.

## Packaging and docs

- [x] LICENSE (MIT) and THIRD_PARTY_NOTICES.md present.
- [x] README quick start, boundaries, and development instructions current.
- [x] User guide covers setup, full analysis, queries, review, export,
      plugins/remote, and the safety model.
- [x] Example plugin manifests documented in `plugins/examples/README.md`.
- [x] `scripts/auto-shark-gui.cmd` launcher for Windows desktops.
- [x] Version 0.2.0 with Beta classifier.
- [x] Windows portable package: PyInstaller onedir (shared spec
      `scripts/autoshark.spec`, launchers in `scripts/launcher_*.py`) with
      embedded Python 3.11 and PySide6, `AutoShark.exe` (GUI) and
      `auto-shark.exe` (CLI), LICENSE/notices, and a stable `AutoShark`
      archive root. Packaged CLI probe/analyze/report smoke passed locally.
- [x] Windows installer: Inno Setup `scripts/windows_installer.iss` uses a
      stable AppId and fixed per-user install directory, so a later installer
      upgrades the existing copy in place and preserves projects.
- [x] Reproducible build script `scripts/build_windows_release.ps1` emits the
      installer, portable ZIP, wheel, sdist, and `SHA256SUMS`.
- [x] Tag-triggered GitHub Release workflow published both Windows packages,
      Python distributions, checksums, and generated release notes.

## v0.2.0 release evidence

- [x] Frozen CLI reports `auto-shark 0.2.0`; real-TShark probe, body extraction,
      scan, and JSON report smoke passed on the committed HTTP fixture.
- [x] Frozen GUI remained running under the offscreen Qt backend; the portable
      archive has a stable `AutoShark` root and contains the remote
      `cwd_adapter.py` runtime asset.
- [x] Installed v0.1.1, created a project, added a stale `_internal` marker,
      upgraded in place to v0.2.0, and verified the marker was removed while
      the project remained readable. Silent uninstall removed the application
      directory and preserved the project and its upgrade report.
- [x] GitHub Release v0.2.0 is public with five assets. The published files
      were downloaded and independently verified against its `SHA256SUMS`:
      wheel `fe261a20b601bc2c9400f6422bb702fbc3a074a011c4e615f17a0ff9568a5d2f`,
      sdist `5c0a8d3fa104d0c782edd43a8826d9d3f35f5440ac1d9e06c9b13b23e7c45e2d`,
      portable ZIP `181b4a22eeca8b9276dd43ca85e165ad4ac8a306cf775a2c8e6d7bbf99c320ac`,
      installer `2965bdcc584d2146479d69f01cb2598f0363ce2710ddf5cccf5a5adb49ab1783`.
- [x] The downloaded CI wheel has version 0.2.0 and all new runtime modules;
      the downloaded portable package passes version/probe, adapter-presence,
      and offscreen GUI startup checks.

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
