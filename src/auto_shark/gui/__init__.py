"""Optional PySide6 investigation UI helpers.

This package keeps its top level import-safe without PySide6 so the CLI core
stays usable on Python 3.9 and minimal installs. Widget modules are imported
lazily from :func:`run_gui` only.
"""

from __future__ import annotations

from .app import run_gui as run_gui


def gui_available() -> tuple[bool, str]:
    """Return ``(available, import_error_text)`` for the optional GUI extra."""
    try:
        import PySide6  # noqa: F401
    except ImportError as error:
        return False, str(error)
    return True, ""
