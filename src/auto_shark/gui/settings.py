"""Persistent user settings for the investigation UI."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class GuiSettings:
    tshark_path: Optional[str] = None
    remote_host: Optional[str] = None
    remote_port: int = 22
    ssh_identity: Optional[str] = None
    ssh_path: Optional[str] = None
    sftp_path: Optional[str] = None
    remote_root: str = ".auto-shark-jobs"
    recent_captures: list[str] = field(default_factory=list)
    flag_format: str = ""
    filter_history: list[str] = field(default_factory=list)

    def remember_capture(self, path: Path) -> None:
        entry = str(Path(path).resolve())
        entries = [entry] + [
            item for item in self.recent_captures if Path(item).resolve() != Path(entry).resolve()
        ]
        self.recent_captures = entries[:10]

    def remember_filter(self, text: str) -> None:
        entry = text.strip()
        if not entry:
            return
        self.filter_history = [entry] + [
            item for item in self.filter_history if item != entry
        ][:19]


def settings_path() -> Path:
    base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / ".local" / "share")
    return base / "AutoShark" / "settings.json"


def load_settings() -> GuiSettings:
    path = settings_path()
    if not path.is_file():
        return GuiSettings()
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return GuiSettings()
    if not isinstance(document, dict):
        return GuiSettings()
    known = {field for field in GuiSettings.__dataclass_fields__}
    values = {key: value for key, value in document.items() if key in known}
    raw_port = values.get("remote_port", 22)
    try:
        values["remote_port"] = int(raw_port)
    except (TypeError, ValueError):
        values["remote_port"] = 22
    if not 1 <= int(values["remote_port"]) <= 65535:
        values["remote_port"] = 22
    return GuiSettings(**values)


def save_settings(settings: GuiSettings) -> None:
    path = settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(
        json.dumps(asdict(settings), ensure_ascii=False, sort_keys=True, indent=2),
        encoding="utf-8",
    )
    os.replace(temporary, path)
