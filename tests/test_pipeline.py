from datetime import datetime, timezone

from auto_shark.core.ids import EvidenceLocator, evidence_id
from auto_shark.pipeline import scan_project
from auto_shark.project import create_project
from auto_shark.storage import BlobStore, Database


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def test_scan_project_persists_form_lineage_and_candidate_idempotently(tmp_path) -> None:
    capture = tmp_path / "sample.pcap"
    capture.write_bytes(b"capture")
    project = tmp_path / "sample.auto-shark"
    info = create_project(capture, project)
    database = Database(project / "project.sqlite")
    database.initialize()
    body = b"value=ZmxhZ3twaXBlbGluZX0="
    blob = BlobStore(project / "blobs").put_bytes(body)
    locator = EvidenceLocator(
        capture_sha256=info.capture_sha256,
        source_kind="http-body",
        frame_start=1,
        frame_end=1,
        protocol_message="message",
        byte_length=len(body),
    )
    public_evidence_id = evidence_id(locator)
    with database.connect() as connection:
        capture_id = int(connection.execute("SELECT id FROM capture").fetchone()[0])
        connection.execute(
            "INSERT INTO frame (capture_id,frame_number) VALUES (?,1)", (capture_id,)
        )
        connection.execute(
            "INSERT INTO protocol_message "
            "(message_id,capture_id,representative_frame,protocol,message_kind,fields_json) "
            "VALUES ('message',?,1,'http','request','{}')",
            (capture_id,),
        )
        message_id = int(connection.execute("SELECT id FROM protocol_message").fetchone()[0])
        connection.execute(
            "INSERT INTO http_message (protocol_message_id,content_length,content_type) "
            "VALUES (?,?, 'application/x-www-form-urlencoded')",
            (message_id, len(body)),
        )
        connection.execute(
            "INSERT INTO tool_run "
            "(run_id,tool_name,argv_json,started_at,status) "
            "VALUES ('run','test','[]',?,'completed')",
            (_now(),),
        )
        tool_run_id = int(connection.execute("SELECT id FROM tool_run").fetchone()[0])
        connection.execute(
            "INSERT INTO blob (sha256,byte_length,relative_path,complete,created_at) "
            "VALUES (?,?,?,?,?)",
            (blob.sha256, blob.byte_length, blob.path.relative_to(project).as_posix(), 1, _now()),
        )
        blob_id = int(connection.execute("SELECT id FROM blob").fetchone()[0])
        connection.execute(
            "INSERT INTO evidence "
            "(evidence_id,capture_id,source_kind,frame_start,frame_end,protocol_message_id,"
            "byte_length,blob_id,locator_json) VALUES (?,?,'http-body',1,1,?,?,?,'{}')",
            (public_evidence_id, capture_id, message_id, len(body), blob_id),
        )
        evidence_db_id = int(connection.execute("SELECT id FROM evidence").fetchone()[0])
        connection.execute(
            "INSERT INTO http_body "
            "(protocol_message_id,evidence_id,tool_run_id,declared_length,extracted_length,"
            "status,truncated,updated_at) VALUES (?,?,?,?,?,'complete',0,?)",
            (message_id, evidence_db_id, tool_run_id, len(body), len(body), _now()),
        )

    first = scan_project(project)
    second = scan_project(project)
    assert first.candidate_values == ("flag{pipeline}",)
    assert second.candidate_values == first.candidate_values
    with database.connect() as connection:
        assert connection.execute("SELECT count(1) FROM form_field").fetchone()[0] == 1
        assert connection.execute("SELECT count(1) FROM transform").fetchone()[0] == 2
        assert connection.execute("SELECT count(1) FROM candidate").fetchone()[0] == 1
        match = connection.execute(
            "SELECT e.source_kind,e.byte_offset,e.byte_length FROM candidate_evidence ce "
            "JOIN evidence e ON e.id=ce.evidence_id"
        ).fetchone()
        assert tuple(match) == ("flag-match", 0, len(b"flag{pipeline}"))


def test_scan_project_enforces_first_transform_output_budget(tmp_path) -> None:
    capture = tmp_path / "sample.pcap"
    capture.write_bytes(b"capture")
    project = tmp_path / "sample.auto-shark"
    info = create_project(capture, project)
    database = Database(project / "project.sqlite")
    database.initialize()
    body = b"value=ZmxhZ3twaXBlbGluZX0="
    blob = BlobStore(project / "blobs").put_bytes(body)
    locator = EvidenceLocator(
        capture_sha256=info.capture_sha256,
        source_kind="http-body",
        frame_start=1,
        frame_end=1,
        protocol_message="message",
        byte_length=len(body),
    )
    with database.connect() as connection:
        capture_id = int(connection.execute("SELECT id FROM capture").fetchone()[0])
        connection.execute(
            "INSERT INTO frame (capture_id,frame_number) VALUES (?,1)", (capture_id,)
        )
        connection.execute(
            "INSERT INTO protocol_message "
            "(message_id,capture_id,representative_frame,protocol,message_kind,fields_json) "
            "VALUES ('message',?,1,'http','request','{}')",
            (capture_id,),
        )
        message_id = int(connection.execute("SELECT id FROM protocol_message").fetchone()[0])
        connection.execute(
            "INSERT INTO http_message (protocol_message_id,content_length,content_type) "
            "VALUES (?,?, 'application/x-www-form-urlencoded')",
            (message_id, len(body)),
        )
        connection.execute(
            "INSERT INTO tool_run (run_id,tool_name,argv_json,started_at,status) "
            "VALUES ('run','test','[]',?,'completed')",
            (_now(),),
        )
        tool_run_id = int(connection.execute("SELECT id FROM tool_run").fetchone()[0])
        connection.execute(
            "INSERT INTO blob (sha256,byte_length,relative_path,complete,created_at) "
            "VALUES (?,?,?,?,?)",
            (blob.sha256, blob.byte_length, blob.path.relative_to(project).as_posix(), 1, _now()),
        )
        blob_id = int(connection.execute("SELECT id FROM blob").fetchone()[0])
        body_evidence_id = evidence_id(locator)
        connection.execute(
            "INSERT INTO evidence "
            "(evidence_id,capture_id,source_kind,frame_start,frame_end,protocol_message_id,"
            "byte_length,blob_id,locator_json) VALUES (?,?,'http-body',1,1,?,?,?,'{}')",
            (body_evidence_id, capture_id, message_id, len(body), blob_id),
        )
        evidence_db_id = int(connection.execute("SELECT id FROM evidence").fetchone()[0])
        connection.execute(
            "INSERT INTO http_body "
            "(protocol_message_id,evidence_id,tool_run_id,declared_length,extracted_length,"
            "status,truncated,updated_at) VALUES (?,?,?,?,?,'complete',0,?)",
            (message_id, evidence_db_id, tool_run_id, len(body), len(body), _now()),
        )

    summary = scan_project(project, max_transform_output_bytes=4, max_transform_total_bytes=4)
    assert summary.form_fields == 1
    assert summary.transforms == 0
    assert summary.candidates == 0
