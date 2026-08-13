import sqlite3

import pytest

from auto_shark.storage.database import APPLICATION_ID, SCHEMA_VERSION, Database


def test_database_initialization_is_idempotent(tmp_path) -> None:
    database = Database(tmp_path / "project.sqlite")
    database.initialize()
    database.initialize()
    with database.connect() as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
        assert connection.execute("PRAGMA application_id").fetchone()[0] == APPLICATION_ID
        assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        journal_mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
        assert str(journal_mode).lower() == "wal"
    assert {"capture", "evidence", "candidate", "transform"}.issubset(set(database.table_names()))


def test_database_rejects_future_schema(tmp_path) -> None:
    path = tmp_path / "future.sqlite"
    with sqlite3.connect(path) as connection:
        connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 1}")
    with pytest.raises(ValueError, match="newer"):
        Database(path).initialize()
