"""Typed configuration loaded from explicit arguments and environment variables."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class Settings:
    tshark_path: Optional[Path]
    project_root: Path
    subprocess_timeout_seconds: float = 30.0
    stdout_limit_bytes: int = 16 * 1024 * 1024
    stderr_limit_bytes: int = 256 * 1024

    @classmethod
    def from_environment(cls, environ: Optional[Mapping[str, str]] = None) -> Settings:
        values = os.environ if environ is None else environ
        local_app_data = Path(values.get("LOCALAPPDATA", Path.home() / ".local" / "share"))
        tshark = values.get("AUTO_SHARK_TSHARK")
        project_root = values.get("AUTO_SHARK_PROJECT_ROOT")
        return cls(
            tshark_path=Path(tshark).expanduser() if tshark else None,
            project_root=(
                Path(project_root).expanduser()
                if project_root
                else local_app_data / "AutoShark" / "projects"
            ),
        )
