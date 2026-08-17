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


def test_schema_nine_database_migrates_to_telnet_schema(tmp_path) -> None:
    path = tmp_path / "schema-nine.sqlite"
    database = Database(path)
    with database.connect() as connection:
        for script in MIGRATIONS[:9]:
            connection.executescript(script)
        connection.execute(f"PRAGMA application_id = {APPLICATION_ID}")
        connection.execute("PRAGMA user_version = 9")
    database.initialize()
    with database.connect() as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
    assert {
        "telnet_dialogue",
        "telnet_dialogue_run",
        "telnet_metadata_skip",
        "telnet_record",
        "telnet_record_source",
        "telnet_record_relation",
        "telnet_parse_skip",
    }.issubset(set(database.table_names()))


def test_schema_ten_database_migrates_to_inventory_schema(tmp_path) -> None:
    database = Database(tmp_path / "project.sqlite")
    database.initialize()
    with database.connect() as connection:
        connection.execute("PRAGMA user_version = 10")
        for table in (
            "manual_task_evidence",
            "manual_task_signal",
            "manual_task",
            "manual_queue_run",
            "finding_run",
            "multipart_part_artifact",
            "multipart_part",
            "analysis_coverage",
            "inventory_skip",
            "conversation_profile_run",
            "conversation_profile",
            "protocol_observation",
            "capture_inventory_run",
        ):
            connection.execute(f"DROP TABLE {table}")
    database.initialize()
    assert {
        "capture_inventory_run",
        "protocol_observation",
        "conversation_profile",
        "conversation_profile_run",
        "inventory_skip",
        "analysis_coverage",
        "multipart_part",
        "multipart_part_artifact",
        "finding_run",
        "manual_queue_run",
        "manual_task",
        "manual_task_signal",
        "manual_task_evidence",
    }.issubset(set(database.table_names()))


def test_early_schema_eleven_database_repairs_slice_three_tables(tmp_path) -> None:
    database = Database(tmp_path / "project.sqlite")
    database.initialize()
    with database.connect() as connection:
        for table in (
            "manual_task_evidence",
            "manual_task_signal",
            "manual_task",
            "manual_queue_run",
            "finding_run",
            "multipart_part_artifact",
            "multipart_part",
        ):
            connection.execute(f"DROP TABLE {table}")
        connection.execute("PRAGMA user_version = 11")
    database.initialize()
    assert {
        "multipart_part",
        "multipart_part_artifact",
        "finding_run",
        "manual_queue_run",
        "manual_task",
        "manual_task_signal",
        "manual_task_evidence",
    }.issubset(set(database.table_names()))


def test_schema_twelve_database_migrates_to_m4_detector_schema(tmp_path) -> None:
    database = Database(tmp_path / "project.sqlite")
    database.initialize()
    with database.connect() as connection:
        connection.execute("PRAGMA user_version = 12")
    database.initialize()
    assert {
        "detector_run",
        "detector_skip",
        "behavior_event",
        "behavior_event_evidence",
        "behavior_event_run",
    }.issubset(set(database.table_names()))
    with database.connect() as connection:
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_schema_thirteen_database_migrates_to_investigation_notes(tmp_path) -> None:
    database = Database(tmp_path / "project.sqlite")
    database.initialize()
    with database.connect() as connection:
        connection.execute("DROP TABLE investigation_note")
        connection.execute("PRAGMA user_version = 13")
    database.initialize()
    assert "investigation_note" in set(database.table_names())
    with database.connect() as connection:
        columns = {
            str(row[1]) for row in connection.execute("PRAGMA table_info(investigation_note)")
        }
        assert {"note_id", "capture_id", "legacy_note_id"}.issubset(columns)
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_schema_fourteen_database_migrates_to_plugin_tables(tmp_path) -> None:
    database = Database(tmp_path / "project.sqlite")
    database.initialize()
    with database.connect() as connection:
        for table in (
            "plugin_manifest",
            "plugin_run_detail",
            "plugin_output",
            "plugin_output_skip",
        ):
            connection.execute(f"DROP TABLE {table}")
        connection.execute("PRAGMA user_version = 14")
    database.initialize()
    tables = set(database.table_names())
    assert {
        "plugin_manifest",
        "plugin_run_detail",
        "plugin_output",
        "plugin_output_skip",
    }.issubset(tables)
    with database.connect() as connection:
        run_row = connection.execute(
            "INSERT INTO plugin_run"
            "(run_id,plugin_id,plugin_version,input_artifact_id,job_directory,status,"
            "result_schema,started_at,ended_at) "
            "VALUES('run-1','manifest-1','1.0',NULL,'jobs/plugins/run-1','completed',"
            "'auto-shark.plugin-run/v1','2026-08-17T00:00:00+00:00',NULL)"
        ).fetchone()
        assert run_row is None
        run_id = int(
            connection.execute("SELECT id FROM plugin_run WHERE run_id='run-1'").fetchone()[0]
        )
        connection.execute(
            "INSERT INTO plugin_output(plugin_run_id,relative_path,byte_length,sha256) "
            "VALUES(?, 'result.json', 2, 'hash')",
            (run_id,),
        )
        connection.execute(
            "INSERT INTO plugin_output_skip(plugin_run_id,relative_path,reason) "
            "VALUES(?, 'big.bin', 'file-byte-limit')",
            (run_id,),
        )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO plugin_output_skip(plugin_run_id,relative_path,reason) "
                "VALUES(?, 'x', 'not-a-reason')",
                (run_id,),
            )
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
