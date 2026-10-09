# v0.4.0 release checklist

Status legend: [x] verified with recorded evidence, [ ] pending execution.

## Code and acceptance

- [x] Focused SMTP/database/CLI/inventory/queue/reporting/GUI regression passes
      after explicit incomplete-DATA provenance was added: 74 passed.
- [x] Real DDCTF SMTP-only rerun recovers eight complete messages and one
      complete PNG attachment, with one explicit incomplete DATA at stream
      2007/frame 8280. Integrity, foreign keys, 135 Blob hashes, and empty jobs
      pass; FTP stream 2005 was not analyzed.
- [x] Ruff, compileall, and `git diff --check` pass on the release tree.
- [x] Full Windows Python 3.11 suite on this tree passes with portable
      TShark 4.6.7: 346 passed in 45.42s.
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
- [x] Version metadata is 0.4.0 with the existing Beta classifier.
- [x] Windows installer offers per-user vs all-users via
      `PrivilegesRequiredOverridesAllowed=dialog` and `{autopf}`.
- [x] GUI remote Linux settings document user@host, port, SSH key / ssh-agent.
- [x] GUI Notes menu and page are removed; CLI notes remain.
- [x] `PROJECT_STATE.md` and `docs/ROADMAP.md` contain final release evidence.

## Windows packages

- [x] Installer script selects `{autopf}` and
      `PrivilegesRequiredOverridesAllowed=dialog` (static test
      `test_windows_release.py`).
- [x] Tag workflow `.github/workflows/release.yml` still requires both
      Windows packages, wheel, sdist, and `SHA256SUMS`.
- [x] GitHub Actions `v0.4.0` run builds Setup.exe, Portable.zip, wheel,
      sdist, and `SHA256SUMS`.

## Published release

- [x] Main commit and annotated `v0.4.0` tag are pushed.
- [x] Tag-triggered GitHub Actions release workflow completes successfully.
- [x] GitHub Release v0.4.0 exposes installer, portable ZIP, wheel, sdist, and
      `SHA256SUMS`.

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
