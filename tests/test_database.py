import sqlite3

import pytest

from auto_shark.storage.database import APPLICATION_ID, SCHEMA_VERSION, Database
from auto_shark.storage.migrations import MIGRATIONS


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


def test_schema_one_database_migrates_to_current(tmp_path) -> None:
    path = tmp_path / "old.sqlite"
    database = Database(path)
    with database.connect() as connection:
        connection.executescript(MIGRATIONS[0])
        connection.execute(f"PRAGMA application_id = {APPLICATION_ID}")
        connection.execute("PRAGMA user_version = 1")
    database.initialize()
    with database.connect() as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    assert {"http_message", "transaction_message"}.issubset(set(database.table_names()))


def test_schema_five_database_migrates_to_file_carving_schema(tmp_path) -> None:
    path = tmp_path / "schema-five.sqlite"
    database = Database(path)
    with database.connect() as connection:
        for script in MIGRATIONS[:5]:
            connection.executescript(script)
        connection.execute(f"PRAGMA application_id = {APPLICATION_ID}")
        connection.execute("PRAGMA user_version = 5")
    database.initialize()
    with database.connect() as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
    assert {"file_scan", "file_carve", "artifact_evidence"}.issubset(set(database.table_names()))


def test_schema_six_database_migrates_to_tcp_reconstruction_schema(tmp_path) -> None:
    path = tmp_path / "schema-six.sqlite"
    database = Database(path)
    with database.connect() as connection:
        for script in MIGRATIONS[:6]:
            connection.executescript(script)
        connection.execute(f"PRAGMA application_id = {APPLICATION_ID}")
        connection.execute("PRAGMA user_version = 6")
    database.initialize()
    with database.connect() as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
    assert {
        "tcp_segment",
        "tcp_segment_run",
        "tcp_segment_skip",
        "tcp_reconstruction",
        "tcp_reconstruction_source",
        "tcp_gap",
        "tcp_overlap_conflict",
    }.issubset(set(database.table_names()))


def test_schema_seven_database_migrates_to_triage_schema(tmp_path) -> None:
    path = tmp_path / "schema-seven.sqlite"
    database = Database(path)
    with database.connect() as connection:
        for script in MIGRATIONS[:7]:
            connection.executescript(script)
        connection.execute(f"PRAGMA application_id = {APPLICATION_ID}")
        connection.execute("PRAGMA user_version = 7")
    database.initialize()
    with database.connect() as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        scan_columns = {str(row[1]) for row in connection.execute("PRAGMA table_info(triage_scan)")}
    assert {"triage_scan", "candidate_signal"}.issubset(set(database.table_names()))
    assert {"policy_json", "error"}.issubset(scan_columns)


def test_schema_eight_database_migrates_to_ftp_schema(tmp_path) -> None:
    path = tmp_path / "schema-eight.sqlite"
    database = Database(path)
    with database.connect() as connection:
        for script in MIGRATIONS[:8]:
            connection.executescript(script)
        connection.execute(f"PRAGMA application_id = {APPLICATION_ID}")
        connection.execute("PRAGMA user_version = 8")
    database.initialize()
    with database.connect() as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
    assert {
        "ftp_message",
        "ftp_data_message",
        "ftp_message_run",
        "ftp_metadata_skip",
        "ftp_transfer",
        "ftp_transfer_message",
    }.issubset(set(database.table_names()))
