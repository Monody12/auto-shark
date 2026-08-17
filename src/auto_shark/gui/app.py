"""Application bootstrap for the investigation UI."""

from __future__ import annotations

import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Optional


def run_gui(
    project_path: Optional[Path] = None, argv: Optional[Sequence[str]] = None
) -> int:
    """Launch the Auto-Shark investigation UI. Returns a process exit code."""
    try:
        from PySide6.QtWidgets import QApplication
    except ImportError as error:
        print(
            "error: the GUI requires the optional 'gui' extra (PySide6): "
            f"{error}\n"
            "install it with: uv sync --extra gui  or  pip install auto-shark[gui]",
            file=sys.stderr,
        )
        return 2

    from .main_window import MainWindow

    application = QApplication(list(sys.argv[:1] if argv is None else argv))
    window = MainWindow()
    window.show()
    if project_path is not None:
        window.open_project(Path(project_path))
    return application.exec()
