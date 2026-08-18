"""Application bootstrap for the investigation UI."""

from __future__ import annotations

import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Optional

from .i18n import translate


def display_available() -> tuple[bool, str]:
    """Best-effort detection of a usable display for the Qt GUI.

    Windows always has an interactive desktop in a user session. On POSIX the
    X11/Wayland environment variables must indicate a reachable display; an
    SSH session with forwarded but broken display variables is detected as
    unavailable so the CLI fallback message is shown instead of a Qt crash.
    """
    if sys.platform == "win32":
        return True, ""
    session = os.environ.get("XDG_SESSION_TYPE", "")
    if session in ("x11", "wayland"):
        return True, ""
    if os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"):
        return True, ""
    return (
        False,
        "no DISPLAY/WAYLAND_DISPLAY and no XDG_SESSION_TYPE=x11/wayland detected",
    )


def run_gui(
    project_path: Optional[Path] = None, argv: Optional[Sequence[str]] = None
) -> int:
    """Launch the Auto-Shark investigation UI. Returns a process exit code."""
    try:
        from PySide6.QtWidgets import QApplication
    except ImportError as error:
        prefix = translate("error: the GUI requires the optional 'gui' extra (PySide6):")
        install = translate("install it with: uv sync --extra gui  or  pip install auto-shark[gui]")
        print(
            f"{prefix} {error}\n{install}",
            file=sys.stderr,
        )
        return 2
    available, reason = display_available()
    if not available:
        print(
            f"{translate('error: no usable display for the GUI')} ({reason}).\n"
            f"{translate('Use the command-line interface instead: auto-shark --help')}",
            file=sys.stderr,
        )
        return 2

    from .main_window import MainWindow

    try:
        application = QApplication(list(sys.argv[:1] if argv is None else argv))
    except Exception as error:  # noqa: BLE001 - Qt runtime/display failures
        print(
            f"{translate('error: the GUI could not start')} ({error}).\n"
            f"{translate('Use the command-line interface instead: auto-shark --help')}",
            file=sys.stderr,
        )
        return 2
    window = MainWindow()
    window.show()
    if project_path is not None:
        window.open_project(Path(project_path))
    return application.exec()
