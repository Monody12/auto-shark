"""Static gates for the two Windows release forms."""

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_installer_has_stable_upgrade_identity_and_directory() -> None:
    script = (ROOT / "scripts" / "windows_installer.iss").read_text(encoding="utf-8")
    assert "AppId={{F4B24FB8-7432-49E0-A0B6-22D154A555F2}" in script
    assert "DefaultDirName={localappdata}\\Programs\\Auto-Shark" in script
    assert "UsePreviousAppDir=yes" in script
    assert "OutputBaseFilename=AutoShark-Windows-x64-Setup" in script
    assert "{app}\\_internal" in script


def test_portable_archive_uses_a_stable_root_directory() -> None:
    script = (ROOT / "scripts" / "build_windows_release.ps1").read_text(
        encoding="utf-8"
    )
    assert '"portable-stage"' in script
    assert '"AutoShark"' in script
    assert '"AutoShark-Windows-x64-Portable.zip"' in script
    assert "Compress-Archive -LiteralPath $PortableRoot" in script


def test_tag_release_requires_both_windows_packages() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(
        encoding="utf-8"
    )
    assert "-RequireInstaller" in workflow
    assert "AutoShark-Windows-x64-Setup.exe" in workflow
    assert "AutoShark-Windows-x64-Portable.zip" in workflow
    assert "${{ runner.temp }}\\release\\SHA256SUMS" in workflow
    assert "generate_release_notes: true" in workflow


def test_frozen_cli_includes_the_remote_cwd_adapter_as_data() -> None:
    spec = (ROOT / "scripts" / "autoshark.spec").read_text(encoding="utf-8")
    assert '"cwd_adapter.py"' in spec
    assert '"auto_shark/assets"' in spec
    assert "datas=CWD_ADAPTER_DATA" in spec
