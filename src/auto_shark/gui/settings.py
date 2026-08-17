"""Persistent user settings for the investigation UI."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional


@dataclass
class GuiSettings:
    tshark_path: Optional[str] = None
    remote_host: Optional[str] = None
    ssh_path: Optional[str] = None
    sftp_path: Optional[str] = None
    remote_root: str = ".auto-shark-jobs"


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
    return GuiSettings(
        **{key: value for key, value in document.items() if key in known}
    )


def save_settings(settings: GuiSettings) -> None:
    path = settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(
        json.dumps(asdict(settings), ensure_ascii=False, sort_keys=True, indent=2),
        encoding="utf-8",
    )
    os.replace(temporary, path)
