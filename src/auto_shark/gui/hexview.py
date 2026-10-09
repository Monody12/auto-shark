"""Read-only hex+ASCII content viewer for streams, bodies, and dialogues."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

_HEX_COLUMNS = 16
_VIEW_LIMIT = 512 * 1024


def hexdump(data: bytes, *, base_offset: int = 0, limit: int = _VIEW_LIMIT) -> str:
    """Render classic 16-byte hex+ASCII lines; bounded for UI safety."""

    shown = data[:limit]
    lines: list[str] = []
    for start in range(0, len(shown), _HEX_COLUMNS):
        chunk = shown[start : start + _HEX_COLUMNS]
        hex_part = " ".join(f"{byte:02x}" for byte in chunk)
        ascii_part = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in chunk)
        lines.append(f"{base_offset + start:08x}  {hex_part:<47}  {ascii_part}")
    if len(data) > limit:
        lines.append(f"… ({len(data) - limit} more bytes not shown)")
    return "\n".join(lines)


def printable_text(data: bytes, *, limit: int = _VIEW_LIMIT) -> str:
    shown = data[:limit]
    return "".join(chr(byte) if 32 <= byte < 127 or byte in (9, 10, 13) else "." for byte in shown)


class BytesViewerDialog(QDialog):
    """Modal dialog showing bytes as hex+ASCII with a plain-text toggle."""

    def __init__(self, parent: QWidget | None, title: str, data: bytes, note: str = "") -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(860, 560)
        self._data = data
        layout = QVBoxLayout(self)
        meta = QLabel(note or f"{len(data)} bytes")
        layout.addWidget(meta)
        self._text = QPlainTextEdit()
        self._text.setReadOnly(True)
        self._text.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        font = QFont("Consolas")
        font.setStyleHint(QFont.StyleHint.Monospace)
        self._text.setFont(font)
        layout.addWidget(self._text, 1)
        toggle = QPushButton("Hex / ASCII")
        toggle.clicked.connect(self._toggle)
        layout.addWidget(toggle)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        buttons.addButton(QDialogButtonBox.StandardButton.Close).clicked.connect(self.accept)
        layout.addWidget(buttons)
        self._hex_mode = True
        self._render()

    def _toggle(self) -> None:
        self._hex_mode = not self._hex_mode
        self._render()

    def _render(self) -> None:
        if self._hex_mode:
            self._text.setPlainText(hexdump(self._data))
        else:
            self._text.setPlainText(printable_text(self._data))


def view_bytes(parent: QWidget | None, title: str, data: bytes, note: str = "") -> None:
    dialog = BytesViewerDialog(parent, title, data, note)
    dialog.exec()


def view_text(parent: QWidget | None, title: str, text: str, note: str = "") -> None:
    """Show already-decoded text (e.g. Telnet previews) in the same viewer."""

    dialog = BytesViewerDialog(parent, title, text.encode("utf-8", errors="replace"), note)
    dialog._hex_mode = False
    dialog._render()
    dialog.exec()


def read_bounded(path: Path, limit: int = _VIEW_LIMIT) -> bytes:
    with Path(path).open("rb") as stream:
        return stream.read(limit + 1)
