import pytest

import auto_shark.sql_detection as sql_detection
from auto_shark.core.ids import EvidenceLocator, evidence_id
from auto_shark.project import create_project
from auto_shark.sql_detection import (
    classify_sql_value,
    detect_sql_injection,
    parse_query_parameters,
)
from auto_shark.storage import BlobStore, Database


def _project(tmp_path):
    capture = tmp_path / "capture.pcap"
    capture.write_bytes(b"pcap")
    root = tmp_path / "sql.auto-shark"
    info = create_project(capture, root, allow_synced=True)
    database = Database(root / "project.sqlite")
    with database.connect() as connection:
        capture_id = int(connection.execute("SELECT id FROM capture").fetchone()[0])
        for frame in range(1, 7):
            connection.execute(
                "INSERT INTO frame(capture_id,frame_number) VALUES(?,?)", (capture_id, frame)
            )
        requests = (
            ("request-1", 1, "/login?id=1"),
            ("request-3", 3, "/login?id=1%27+OR+1%3D1--"),
            ("request-5", 5, "/login?id=1%27+OR+1%3D1--"),
        )
        responses = (
            ("response-2", 2, 200, 100),
            ("response-4", 4, 500, 20),
            ("response-6", 6, 500, 20),
        )
        message_ids = {}
        for message_id, frame, uri in requests:
            connection.execute(
                "INSERT INTO protocol_message "
                "(message_id,capture_id,representative_frame,protocol,message_kind,fields_json) "
                "VALUES(?,?,?,'http','request','{}')",
                (message_id, capture_id, frame),
            )
            message_ids[message_id] = int(
                connection.execute("SELECT last_insert_rowid()").fetchone()[0]
            )
            connection.execute(
                "INSERT INTO http_message(protocol_message_id,method,uri) VALUES(?,'GET',?)",
                (message_ids[message_id], uri),
            )
        for message_id, frame, code, length in responses:
            connection.execute(
                "INSERT INTO protocol_message "
                "(message_id,capture_id,representative_frame,protocol,message_kind,fields_json) "
                "VALUES(?,?,?,'http','response','{}')",
                (message_id, capture_id, frame),
            )
            message_ids[message_id] = int(
                connection.execute("SELECT last_insert_rowid()").fetchone()[0]
            )
            connection.execute(
                "INSERT INTO http_message(protocol_message_id,response_code,content_length) "
                "VALUES(?,?,?)",
                (message_ids[message_id], code, length),
            )
        for transaction_id, request, response in (
            ("transaction-1", "request-1", "response-2"),
            ("transaction-3", "request-3", "response-4"),
            ("transaction-5", "request-5", "response-6"),
        ):
            connection.execute(
                "INSERT INTO transaction_record "
                "(transaction_id,capture_id,protocol,request_message_id,"
                "response_message_id,status) "
                "VALUES(?,?, 'http',?,?, 'matched')",
                (transaction_id, capture_id, message_ids[request], message_ids[response]),
            )
    return root, database, info


def _add_form_field(database, root, info, message_public_id, frame, value):
    data = value.encode("utf-8")
    blob = BlobStore(root / "blobs").put_bytes(data)
    locator = EvidenceLocator(
        capture_sha256=info.capture_sha256,
        source_kind="transform-output",
        frame_start=frame,
        frame_end=frame,
        protocol_message=message_public_id,
        byte_length=len(data),
        field_name="search",
    )
    with database.connect() as connection:
        capture_id = int(connection.execute("SELECT id FROM capture").fetchone()[0])
        message_id = int(
            connection.execute(
                "SELECT id FROM protocol_message WHERE message_id=?", (message_public_id,)
            ).fetchone()[0]
        )
        connection.execute(
            "INSERT INTO blob(sha256,byte_length,relative_path,complete,created_at) "
            "VALUES(?,?,?,1,datetime('now'))",
            (blob.sha256, len(data), blob.path.relative_to(root).as_posix()),
        )
        blob_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
        connection.execute(
            "INSERT INTO evidence "
            "(evidence_id,capture_id,source_kind,frame_start,frame_end,protocol_message_id,"
            "byte_length,field_name,text_value,blob_id,locator_json) "
            "VALUES(?,?,'transform-output',?,?,?,?,'search',?,?, '{}')",
            (
                evidence_id(locator),
                capture_id,
                frame,
                frame,
                message_id,
                len(data),
                value,
                blob_id,
            ),
        )
        evidence_db_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
        connection.execute(
            "INSERT INTO form_field "
            "(protocol_message_id,ordinal,name,raw_value_evidence_id,decoded_value_evidence_id) "
            "VALUES(?,0,'search',?,?)",
            (message_id, evidence_db_id, evidence_db_id),
        )


def test_sql_classifier_requires_structured_signals() -> None:
    assert classify_sql_value("select a report").signals == ()
    result = classify_sql_value("1' OR 1=1--")
    assert result.signals == ("boolean-expression", "comment-truncation")
    assert result.confidence > 0.7


def test_query_parser_preserves_decoded_values_and_raw_offsets() -> None:
    result = parse_query_parameters("/login?id=1%27+OR+1%3D1--&name=user")
    assert [(item.name, item.value, item.value_offset, item.raw_length) for item in result] == [
        ("id", "1' OR 1=1--", 10, 15),
        ("name", "user", 31, 4),
    ]


def test_sql_detection_persists_comparison_events_and_deduplicates_repeats(tmp_path) -> None:
    root, database, _ = _project(tmp_path)

    first = detect_sql_injection(root)
    second = detect_sql_injection(root)

    assert first.transactions_processed == second.transactions_processed == 3
    assert first.events == second.events == 2
    assert first.findings == second.findings == 1
    with database.connect() as connection:
        events = connection.execute(
            "SELECT event_kind,status,request_frame,duplicate_of,confidence "
            "FROM behavior_event ORDER BY request_frame"
        ).fetchall()
        evidence_roles = {
            row[0] for row in connection.execute("SELECT role FROM behavior_event_evidence")
        }
        findings = int(connection.execute("SELECT count(*) FROM finding").fetchone()[0])
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
    assert [(row[0], row[1], row[2]) for row in events] == [
        ("sql-injection-probe", "complete", 3),
        ("sql-injection-probe", "complete", 5),
    ]
    assert events[0][3] is None
    assert events[1][3] is not None
    assert events[0][4] > 0.7
    assert evidence_roles == {"request-parameter", "response", "clean-baseline"}
    assert findings == 1


def test_sql_detection_without_baseline_is_partial(tmp_path) -> None:
    root, database, _ = _project(tmp_path)
    with database.connect() as connection:
        connection.execute("DELETE FROM transaction_record WHERE transaction_id='transaction-1'")
    result = detect_sql_injection(root)
    assert result.events == 2
    with database.connect() as connection:
        rows = connection.execute(
            "SELECT status,confidence FROM behavior_event ORDER BY request_frame"
        ).fetchall()
    assert [row[0] for row in rows] == ["partial", "partial"]
    assert all(row[1] <= 0.7 for row in rows)


def test_sql_detection_with_truncated_response_is_partial(tmp_path) -> None:
    root, database, _ = _project(tmp_path)
    with database.connect() as connection:
        connection.execute(
            "INSERT INTO tool_run(run_id,tool_name,argv_json,started_at,status) "
            "VALUES('truncated-body','test','[]',datetime('now'),'completed')"
        )
        tool_run_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
        response_id = int(
            connection.execute(
                "SELECT id FROM protocol_message WHERE message_id='response-4'"
            ).fetchone()[0]
        )
        connection.execute(
            "INSERT INTO http_body(protocol_message_id,tool_run_id,declared_length,"
            "extracted_length,status,truncated,updated_at) "
            "VALUES(?,?,20,10,'limit-truncated',1,datetime('now'))",
            (response_id, tool_run_id),
        )

    result = detect_sql_injection(root)

    assert result.status == "partial"
    with database.connect() as connection:
        statuses = connection.execute(
            "SELECT request_frame,status FROM behavior_event ORDER BY request_frame"
        ).fetchall()
    assert [tuple(row) for row in statuses] == [(3, "partial"), (5, "complete")]


def test_sql_detection_reads_bounded_url_form_evidence(tmp_path) -> None:
    root, database, info = _project(tmp_path)
    _add_form_field(database, root, info, "request-1", 1, "normal search")
    _add_form_field(
        database,
        root,
        info,
        "request-3",
        3,
        "x' UNION SELECT password FROM users-- ",
    )

    result = detect_sql_injection(root)

    assert result.events == 3
    assert result.findings == 2
    with database.connect() as connection:
        row = connection.execute(
            "SELECT target,detail_json FROM behavior_event WHERE target='GET /login#search'"
        ).fetchone()
    assert row is not None
    assert "union-select" in row[1]


def test_sql_detection_records_transaction_budget(tmp_path) -> None:
    root, database, _ = _project(tmp_path)

    result = detect_sql_injection(root, max_transactions=1)

    assert result.status == "budget-limited"
    assert result.transactions_processed == 1
    with database.connect() as connection:
        skipped = connection.execute(
            "SELECT sum(count) FROM detector_skip WHERE reason='transaction-limit'"
        ).fetchone()[0]
    assert skipped == 2


def test_sql_detection_applies_parameter_limit_across_the_run(tmp_path) -> None:
    root, database, _ = _project(tmp_path)

    result = detect_sql_injection(root, max_parameters=2)

    assert result.status == "budget-limited"
    assert result.parameters_processed == 2
    assert result.events == 1
    assert result.inputs_skipped == 1
    with database.connect() as connection:
        run = connection.execute(
            "SELECT inputs_processed,inputs_skipped FROM detector_run WHERE run_id=?",
            (result.run_id,),
        ).fetchone()
        skipped = connection.execute(
            "SELECT sum(count) FROM detector_skip WHERE detector_run_id="
            "(SELECT id FROM detector_run WHERE run_id=?) AND reason='parameter-limit'",
            (result.run_id,),
        ).fetchone()[0]
    assert tuple(run) == (2, 1)
    assert skipped == 1


def test_sql_detection_records_event_limit(tmp_path) -> None:
    root, database, _ = _project(tmp_path)

    result = detect_sql_injection(root, max_events=1)

    assert result.status == "budget-limited"
    assert result.events == 1
    assert result.inputs_skipped == 1
    with database.connect() as connection:
        skipped = connection.execute(
            "SELECT count(*) FROM detector_skip WHERE detector_run_id="
            "(SELECT id FROM detector_run WHERE run_id=?) AND reason='event-limit'",
            (result.run_id,),
        ).fetchone()[0]
    assert skipped == 1


def test_sql_detection_finding_limit_counts_existing_findings(tmp_path) -> None:
    root, database, _ = _project(tmp_path)
    with database.connect() as connection:
        connection.execute(
            "UPDATE http_message SET uri='/login?name=1%27+OR+1%3D1--' "
            "WHERE protocol_message_id="
            "(SELECT id FROM protocol_message WHERE message_id='request-5')"
        )
    assert detect_sql_injection(root).findings == 2

    result = detect_sql_injection(root, max_findings=1)

    assert result.status == "budget-limited"
    assert result.findings == 1
    assert result.inputs_skipped == 1
    with database.connect() as connection:
        run = connection.execute(
            "SELECT findings FROM detector_run WHERE run_id=?", (result.run_id,)
        ).fetchone()[0]
        skipped = connection.execute(
            "SELECT count(*) FROM detector_skip WHERE detector_run_id="
            "(SELECT id FROM detector_run WHERE run_id=?) AND reason='finding-limit'",
            (result.run_id,),
        ).fetchone()[0]
    assert run == 1
    assert skipped == 1


def test_sql_detection_records_missing_form_blob_as_partial(tmp_path) -> None:
    root, database, info = _project(tmp_path)
    _add_form_field(
        database,
        root,
        info,
        "request-3",
        3,
        "x' UNION SELECT password FROM users-- ",
    )
    with database.connect() as connection:
        connection.execute(
            "UPDATE evidence SET text_value=NULL WHERE field_name='search'"
        )
        relative_path = connection.execute(
            "SELECT b.relative_path FROM form_field ff "
            "JOIN evidence e ON e.id=ff.decoded_value_evidence_id "
            "JOIN blob b ON b.id=e.blob_id WHERE ff.name='search'"
        ).fetchone()[0]
    (root / relative_path).unlink()

    result = detect_sql_injection(root)

    assert result.status == "partial"
    with database.connect() as connection:
        reason = connection.execute(
            "SELECT reason FROM detector_skip WHERE detector_run_id="
            "(SELECT id FROM detector_run WHERE run_id=?)",
            (result.run_id,),
        ).fetchone()[0]
    assert reason == "failed"


def test_sql_detection_marks_detector_and_tool_runs_failed(
    monkeypatch, tmp_path
) -> None:
    root, database, _ = _project(tmp_path)

    def fail_collection(*args, **kwargs):
        raise RuntimeError("synthetic collection failure")

    monkeypatch.setattr(sql_detection, "_collect_parameters", fail_collection)
    with pytest.raises(RuntimeError, match="synthetic collection failure"):
        detect_sql_injection(root)

    with database.connect() as connection:
        detector = connection.execute(
            "SELECT status,inputs_skipped,ended_at FROM detector_run ORDER BY id DESC LIMIT 1"
        ).fetchone()
        tool = connection.execute(
            "SELECT status,exit_code,stderr_text,ended_at FROM tool_run ORDER BY id DESC LIMIT 1"
        ).fetchone()
    assert tuple(detector[:2]) == ("failed", 1)
    assert detector[2] is not None
    assert tuple(tool[:2]) == ("failed", 1)
    assert "synthetic collection failure" in tool[2]
    assert tool[3] is not None
