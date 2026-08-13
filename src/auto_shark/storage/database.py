"""Versioned SQLite access for an Auto-Shark analysis project."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from pathlib import Path

from .migrations import MIGRATIONS

SCHEMA_VERSION = len(MIGRATIONS)
APPLICATION_ID = 0x4153484B  # ASHK


class Database:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.path))
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as connection:
            application_id = int(connection.execute("PRAGMA application_id").fetchone()[0])
            if application_id not in (0, APPLICATION_ID):
                raise ValueError("database belongs to another application")
            current = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if current > SCHEMA_VERSION:
                raise ValueError(
                    f"database schema {current} is newer than supported schema {SCHEMA_VERSION}"
                )
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = NORMAL")
            connection.execute(f"PRAGMA application_id = {APPLICATION_ID}")
            for version, script in enumerate(MIGRATIONS, start=1):
                if version <= current:
                    continue
                connection.executescript(script)
                connection.execute(f"PRAGMA user_version = {version}")

    def table_names(self) -> Iterator[str]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT name FROM sqlite_schema WHERE type = 'table' ORDER BY name"
            )
            yield from (str(row[0]) for row in rows)
