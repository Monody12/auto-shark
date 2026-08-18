import json
from urllib.parse import quote_plus

import pytest

import auto_shark.ognl_detection as ognl_detection
from auto_shark.core.ids import EvidenceLocator, evidence_id
from auto_shark.m4_queries import query_timeline
from auto_shark.ognl_detection import classify_ognl_field_name, detect_ognl_command_injection
from auto_shark.project import create_project
from auto_shark.storage import BlobStore, Database


def _insert_body(
    connection,
    store,
    info,
    capture_id,
    message_id,
    message_public_id,
    frame,
    data,
    tool_run_id,
):
    blob = store.put_bytes(data)
    connection.execute(
        "INSERT OR IGNORE INTO blob(sha256,byte_length,relative_path,complete,created_at) "
        "VALUES(?,?,?,1,datetime('now'))",
        (blob.sha256, len(data), blob.path.relative_to(store.root.parent).as_posix()),
    )
    blob_id = int(
        connection.execute("SELECT id FROM blob WHERE sha256=?", (blob.sha256,)).fetchone()[0]
    )
    locator = EvidenceLocator(
        capture_sha256=info.capture_sha256,
        source_kind="http-body",
        frame_start=frame,
        frame_end=frame,
        protocol_message=message_public_id,
        byte_length=len(data),
    )
    public_id = evidence_id(locator)
    connection.execute(
        "INSERT INTO evidence(evidence_id,capture_id,source_kind,frame_start,frame_end,"
        "protocol_message_id,byte_length,text_value,blob_id,locator_json) "
        "VALUES(?,?,'http-body',?,?,?,?,?,?,?)",
        (
            public_id,
            capture_id,
            frame,
            frame,
            message_id,
            len(data),
            data.decode("utf-8", errors="replace"),
            blob_id,
            "{}",
        ),
    )
    evidence_db_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
    connection.execute(
        "INSERT INTO http_body(protocol_message_id,evidence_id,tool_run_id,declared_length,"
        "extracted_length,status,truncated,updated_at) VALUES(?,?,?,?,?,'complete',0,"
        "datetime('now'))",
        (message_id, evidence_db_id, tool_run_id, len(data), len(data)),
    )
    return evidence_db_id


def _project(tmp_path):
    capture = tmp_path / "capture.pcap"
    capture.write_bytes(b"pcap")
    root = tmp_path / "ognl.auto-shark"
    info = create_project(capture, root, allow_synced=True)
    database = Database(root / "project.sqlite")
    store = BlobStore(root / "blobs")
    expressions = (
        "message=${display.name}",
        "redirect:${#req=#context.get('com.opensymphony.xwork2.dispatcher."
        "HttpServletResponse'),#p=new java.lang.ProcessBuilder('cmd /c ipconfig'),#p.start()}",
        "redirect:${#req=#context.get('com.opensymphony.xwork2.dispatcher."
        "HttpServletResponse'),#p=new java.lang.ProcessBuilder('cmd /c type c:/challenge.txt'),"
        "#p.start()}",
        "redirect:${#req=#context.get('com.opensymphony.xwork2.dispatcher."
        "HttpServletResponse'),#p=new java.lang.ProcessBuilder('cmd /c type c:/challenge.txt'),"
        "#p.start()}",
    )
    with database.connect() as connection:
        capture_id = int(connection.execute("SELECT id FROM capture").fetchone()[0])
        connection.execute(
            "INSERT INTO tool_run(run_id,tool_name,argv_json,started_at,status) "
            "VALUES('body-run','test','[]',datetime('now'),'completed')"
        )
        tool_run_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
        for index, expression in enumerate(expressions):
            request_frame = index * 2 + 1
            response_frame = request_frame + 1
            connection.executemany(
                "INSERT INTO frame(capture_id,frame_number) VALUES(?,?)",
                ((capture_id, request_frame), (capture_id, response_frame)),
            )
            request_public_id = f"request-{request_frame}"
            response_public_id = f"response-{response_frame}"
            connection.execute(
                "INSERT INTO protocol_message(message_id,capture_id,representative_frame,"
                "protocol,message_kind,fields_json) VALUES(?,?,?,'http','request','{}')",
                (request_public_id, capture_id, request_frame),
            )
            request_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
            connection.execute(
                "INSERT INTO protocol_message(message_id,capture_id,representative_frame,"
                "protocol,message_kind,fields_json) VALUES(?,?,?,'http','response','{}')",
                (response_public_id, capture_id, response_frame),
            )
            response_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
            connection.execute(
                "INSERT INTO http_message(protocol_message_id,method,uri,content_type) "
                "VALUES(?,'POST','/struts/action','application/x-www-form-urlencoded')",
                (request_id,),
            )
            connection.execute(
                "INSERT INTO http_message(protocol_message_id,response_code) VALUES(?,200)",
                (response_id,),
            )
            connection.execute(
                "INSERT INTO transaction_record(transaction_id,capture_id,protocol,"
                "request_message_id,response_message_id,status) VALUES(?,?,'http',?,?,'matched')",
                (f"transaction-{request_frame}", capture_id, request_id, response_id),
            )
            body = quote_plus(expression, safe="").encode() + b"="
            _insert_body(
                connection,
                store,
                info,
                capture_id,
                request_id,
                request_public_id,
                request_frame,
                body,
                tool_run_id,
            )
            _insert_body(
                connection,
                store,
                info,
                capture_id,
                response_id,
                response_public_id,
                response_frame,
                f"output-{index}".encode(),
                tool_run_id,
            )
    return root, database


def test_ognl_classifier_requires_context_and_execution_markers() -> None:
    assert classify_ognl_field_name("message=${display.name}") is None
    assert classify_ognl_field_name("${#context.get('x')}") is None
    result = classify_ognl_field_name(
        "${#req=#context.get('x'),#p=new java.lang.ProcessBuilder('id'),#p.start()}"
    )
    assert result is not None
    assert result.command == "id"
    assert "#context" in result.markers and "processbuilder" in result.markers


def test_ognl_detection_preserves_name_ranges_response_links_and_duplicates(tmp_path) -> None:
    root, database = _project(tmp_path)

    first = detect_ognl_command_injection(root, max_preview_bytes=48)
    second = detect_ognl_command_injection(root, max_preview_bytes=48)

    assert first.status == second.status == "completed"
    assert first.transactions_processed == second.transactions_processed == 4
    assert first.fields_processed == second.fields_processed == 4
    assert first.events == second.events == 3
    assert first.findings == second.findings == 1
    with database.connect() as connection:
        events = connection.execute(
            "SELECT request_frame,target,duplicate_of,detail_json FROM behavior_event "
            "ORDER BY request_frame"
        ).fetchall()
        evidence = connection.execute(
            "SELECT e.byte_offset,e.byte_length,e.text_value,b.relative_path "
            "FROM evidence e JOIN blob b ON b.id=e.blob_id "
            "WHERE e.source_kind='form-field-name-injection' ORDER BY e.frame_start"
        ).fetchall()
        roles = {
            tuple(row)
            for row in connection.execute(
                "SELECT role,count(*) FROM behavior_event_evidence GROUP BY role"
            )
        }
        event_runs = int(
            connection.execute("SELECT count(*) FROM behavior_event_run").fetchone()[0]
        )
        finding_runs = int(connection.execute("SELECT count(*) FROM finding_run").fetchone()[0])
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
    assert [row[0] for row in events] == [3, 5, 7]
    assert events[0][1] == "cmd /c ipconfig"
    assert events[2][2] is not None
    assert sum(row[2] is None for row in events) == 2
    assert all(json.loads(row[3])["preview_truncated"] for row in events)
    assert roles == {("field-name", 3), ("response", 3)}
    assert event_runs == 6 and finding_runs == 2
    timeline = query_timeline(root, detector="struts-ognl-command-injection")
    assert timeline.total == timeline.count == 2
    assert timeline.items[0]["event_kind"] == "web-command-execution"
    for offset, length, text, relative_path in evidence:
        raw = (root / relative_path).read_bytes()
        assert offset == 0
        assert raw[offset : offset + length].decode() == quote_plus(text, safe="")


def test_ognl_detection_records_event_and_finding_budgets(tmp_path) -> None:
    root, database = _project(tmp_path)

    result = detect_ognl_command_injection(root, max_events=1, max_findings=1)

    assert result.status == "budget-limited"
    assert result.events == 1 and result.inputs_skipped == 2
    with database.connect() as connection:
        reasons = {
            row[0] for row in connection.execute("SELECT reason FROM detector_skip")
        }
    assert reasons == {"event-limit"}

    second = detect_ognl_command_injection(root, max_findings=1)
    assert second.findings == 1


def test_ognl_detection_skips_a_missing_body_without_failing_the_run(tmp_path) -> None:
    root, database = _project(tmp_path)
    with database.connect() as connection:
        relative_path = connection.execute(
            "SELECT b.relative_path FROM protocol_message pm "
            "JOIN http_body hb ON hb.protocol_message_id=pm.id "
            "JOIN evidence e ON e.id=hb.evidence_id JOIN blob b ON b.id=e.blob_id "
            "WHERE pm.representative_frame=3"
        ).fetchone()[0]
    (root / relative_path).unlink()

    result = detect_ognl_command_injection(root)

    assert result.status == "partial"
    assert result.transactions_processed == 4
    assert result.inputs_skipped == 1
    assert result.events == 2
    with database.connect() as connection:
        run = connection.execute(
            "SELECT status FROM tool_run ORDER BY id DESC LIMIT 1"
        ).fetchone()[0]
        reasons = {
            row[0]
            for row in connection.execute(
                "SELECT reason FROM detector_skip ds JOIN detector_run dr "
                "ON dr.id=ds.detector_run_id ORDER BY ds.id DESC"
            )
        }
    assert run == "completed"
    assert "body-unavailable" in reasons


def test_ognl_detection_marks_failed_runs(monkeypatch, tmp_path) -> None:
    root, database = _project(tmp_path)

    def fail_rows(*args, **kwargs):
        raise RuntimeError("synthetic OGNL failure")

    monkeypatch.setattr(ognl_detection, "_transaction_rows", fail_rows)
    with pytest.raises(RuntimeError, match="synthetic OGNL failure"):
        detect_ognl_command_injection(root)

    with database.connect() as connection:
        detector = connection.execute(
            "SELECT status,inputs_skipped,ended_at FROM detector_run ORDER BY id DESC LIMIT 1"
        ).fetchone()
        tool = connection.execute(
            "SELECT status,exit_code,stderr_text,ended_at FROM tool_run ORDER BY id DESC LIMIT 1"
        ).fetchone()
    assert tuple(detector[:2]) == ("failed", 1) and detector[2] is not None
    assert tuple(tool[:2]) == ("failed", 1)
    assert "synthetic OGNL failure" in tool[2] and tool[3] is not None
