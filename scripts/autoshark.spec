# PyInstaller spec: one shared onedir bundle with the GUI and CLI executables.
# Build from the repository root:
#   uv run --no-sync pyinstaller scripts/autoshark.spec --noconfirm
block_cipher = None

from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules

ROOT = Path(SPECPATH).parent

hiddenimports = collect_submodules("auto_shark") + [
    "auto_shark.assets.cwd_adapter",
]

gui = Analysis(
    [str(ROOT / "scripts" / "launcher_gui.py")],
    pathex=[str(ROOT / "src")],
    binaries=[],
    datas=[],
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    cipher=block_cipher,
)
cli = Analysis(
    [str(ROOT / "scripts" / "launcher_cli.py")],
    pathex=[str(ROOT / "src")],
    binaries=[],
    datas=[],
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    cipher=block_cipher,
)
gui_pyz = PYZ(gui.pure, gui.zipped_data, cipher=block_cipher)
cli_pyz = PYZ(cli.pure, cli.zipped_data, cipher=block_cipher)
gui_exe = EXE(
    gui_pyz,
    gui.scripts,
    [],
    exclude_binaries=True,
    name="AutoShark",
    debug=False,
    bootloader_close_signals=False,
    strip=False,
    upx=False,
    console=False,
)
cli_exe = EXE(
    cli_pyz,
    cli.scripts,
    [],
    exclude_binaries=True,
    name="auto-shark",
    debug=False,
    bootloader_close_signals=False,
    strip=False,
    upx=False,
    console=True,
)
coll = COLLECT(
    gui_exe,
    cli_exe,
    gui.binaries,
    gui.zipfiles,
    gui.datas,
    cli.binaries,
    cli.zipfiles,
    cli.datas,
    strip=False,
    upx=False,
    name="AutoShark",
)
