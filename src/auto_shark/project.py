"""Create and inspect machine-local analysis projects."""

from __future__ import annotations

import json
import os
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .core.hashing import hash_file
from .core.ids import stable_id
from .storage import SCHEMA_VERSION, BlobStore, Database

PROJECT_SUFFIX = ".auto-shark"


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def synced_roots(environ: Optional[dict[str, str]] = None) -> Iterable[Path]:
    values = os.environ if environ is None else environ
    for name, value in values.items():
        if name.upper().startswith("ONEDRIVE") and value:
            yield Path(value).expanduser().resolve()


def ensure_local_project_path(
    path: Path, *, allow_synced: bool = False, roots: Optional[Iterable[Path]] = None
) -> Path:
    resolved = Path(path).expanduser().resolve()
    candidates = synced_roots() if roots is None else roots
    if not allow_synced:
        for root in candidates:
            if _is_relative_to(resolved, Path(root).expanduser().resolve()):
                raise ValueError(
                    "analysis projects cannot be created in a synced directory; "
                    "choose a machine-local path or explicitly use --allow-synced"
                )
    return resolved


@dataclass(frozen=True)
class ProjectInfo:
    root: Path
    capture_path: Path
    capture_sha256: str
    capture_bytes: int
    database_schema: int


def create_project(
    capture_path: Path, project_path: Path, *, allow_synced: bool = False
) -> ProjectInfo:
    capture = Path(capture_path).expanduser().resolve()
    if not capture.is_file():
        raise FileNotFoundError(str(capture))
    root = ensure_local_project_path(project_path, allow_synced=allow_synced)
    if root.exists() and any(root.iterdir()):
        raise FileExistsError(f"project directory is not empty: {root}")
    root.mkdir(parents=True, exist_ok=True)
    for name in ("blobs", "jobs", "logs", "exports"):
        (root / name).mkdir(exist_ok=True)

    capture_sha256, capture_bytes = hash_file(capture)
    database = Database(root / "project.sqlite")
    database.initialize()
    created_at = datetime.now(timezone.utc).isoformat()
    capture_id = stable_id("capture", {"sha256": capture_sha256, "byte_length": capture_bytes})
    with database.connect() as connection:
        connection.execute(
            "INSERT INTO capture "
            "(capture_id, source_name, source_path, byte_length, sha256, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (capture_id, capture.name, str(capture), capture_bytes, capture_sha256, created_at),
        )
        connection.executemany(
            "INSERT INTO project_meta (key, value) VALUES (?, ?)",
            (
                ("project_format", "auto-shark-project/v1"),
                ("created_at", created_at),
                ("capture_id", capture_id),
            ),
        )
    manifest = {
        "schema_version": "auto-shark-project/v1",
        "capture": {
            "path": str(capture),
            "name": capture.name,
            "sha256": capture_sha256,
            "byte_length": capture_bytes,
        },
        "created_at": created_at,
    }
    (root / "project.json").write_text(
        json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    BlobStore(root / "blobs")
    return ProjectInfo(root, capture, capture_sha256, capture_bytes, SCHEMA_VERSION)


def inspect_project(project_path: Path) -> ProjectInfo:
    root = Path(project_path).expanduser().resolve()
    manifest_path = root / "project.json"
    database = Database(root / "project.sqlite")
    if not manifest_path.is_file() or not database.path.is_file():
        raise FileNotFoundError(f"not an Auto-Shark project: {root}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != "auto-shark-project/v1":
        raise ValueError("unsupported project manifest schema")
    with database.connect() as connection:
        schema = int(connection.execute("PRAGMA user_version").fetchone()[0])
    capture = manifest["capture"]
    return ProjectInfo(
        root=root,
        capture_path=Path(capture["path"]),
        capture_sha256=str(capture["sha256"]),
        capture_bytes=int(capture["byte_length"]),
        database_schema=schema,
    )
