from auto_shark.core.ids import EvidenceLocator, evidence_id
from auto_shark.detectors import detect_project, detect_unknown_candidates, scan_unknown_matches
from auto_shark.project import create_project
from auto_shark.storage import BlobStore, Database


def _project_with_body(tmp_path, data: bytes):
    capture = tmp_path / "capture.pcap"
    capture.write_bytes(b"pcap")
    root = tmp_path / "case.auto-shark"
    info = create_project(capture, root, allow_synced=True)
    database = Database(root / "project.sqlite")
    blob = BlobStore(root / "blobs").put_bytes(data)
    with database.connect() as connection:
        capture_id = int(connection.execute("SELECT id FROM capture").fetchone()[0])
        connection.execute("INSERT INTO frame(capture_id,frame_number) VALUES(?,1)", (capture_id,))
        connection.execute(
            "INSERT INTO protocol_message "
            "(message_id,capture_id,representative_frame,protocol,message_kind,fields_json) "
            "VALUES('message-1',?,1,'http','request','{}')",
            (capture_id,),
        )
        message_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
        connection.execute(
            "INSERT INTO http_message(protocol_message_id,method,uri,content_type) "
            "VALUES(?,'POST','/submit','text/plain')",
            (message_id,),
        )
        connection.execute(
            "INSERT INTO tool_run(run_id,tool_name,argv_json,started_at,status) "
            "VALUES('body-run','test','[]',datetime('now'),'completed')"
        )
        tool_run_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
        locator = EvidenceLocator(
            capture_sha256=info.capture_sha256,
            source_kind="http-body",
            frame_start=1,
            frame_end=1,
            protocol_message="message-1",
            byte_length=len(data),
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
            "byte_length,blob_id,locator_json) VALUES(?,?,'http-body',1,1,?,?,?,?)",
            (evidence_id(locator), capture_id, message_id, len(data), blob_id, "{}"),
        )
        evidence_db_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
        connection.execute(
            "INSERT INTO http_body "
            "(protocol_message_id,evidence_id,tool_run_id,declared_length,extracted_length,"
            "status,truncated,updated_at) VALUES(?,?,?,?,?,'complete',0,datetime('now'))",
            (message_id, evidence_db_id, tool_run_id, len(data), len(data)),
        )
    return root, database


def test_unknown_scanner_handles_chunks_and_excludes_obvious_values(tmp_path) -> None:
    path = tmp_path / "evidence.bin"
    unknown = b"acme{Mixed_123}"
    long_token = b"AbcDef1234567890_XyZ-987654"
    path.write_bytes(
        b"flag{known-value} https://example.test/ cookie_name=1234567890AbCdEf_GhIjKl "
        + b"fake{\x01\xffbinary} "
        + unknown
        + b" "
        + long_token
    )

    matches, scanned, truncated, limited = scan_unknown_matches(path, chunk_size=5, max_matches=10)

    assert scanned == path.stat().st_size
    assert not truncated
    assert not limited
    assert [(item.kind, item.value) for item in matches] == [
        ("unknown-brace", unknown),
        ("unknown-token", long_token),
    ]
    assert matches[0].offset == path.read_bytes().index(unknown)


def test_unknown_detection_is_bounded_idempotent_and_queues_brace_candidate(tmp_path) -> None:
    data = b"prefix acme{Mixed_123} and AbcDef1234567890_XyZ-987654 suffix"
    root, database = _project_with_body(tmp_path, data)

    first = detect_project(root, max_evidence_bytes=1024, max_total_bytes=1024, chunk_size=7)
    second = detect_project(root, max_evidence_bytes=1024, max_total_bytes=1024, chunk_size=7)

    assert first.status == second.status == "completed"
    assert first.candidates == second.candidates == 2
    with database.connect() as connection:
        counts = {
            table: int(
                connection.execute(
                    "SELECT count(*) FROM detector_run WHERE detector_set='m4-unknown-candidate'"
                    if table == "detector_run"
                    else f"SELECT count(*) FROM {table}"
                ).fetchone()[0]
            )
            for table in (
                "detector_run",
                "candidate",
                "candidate_evidence",
                "candidate_signal",
                "manual_task",
                "manual_task_signal",
            )
        }
        candidate = connection.execute(
            "SELECT kind,rank_score FROM candidate WHERE normalized_value='acme{Mixed_123}'"
        ).fetchone()
        evidence = connection.execute(
            "SELECT byte_offset,byte_length,frame_start,frame_end FROM evidence "
            "WHERE source_kind='unknown-candidate' ORDER BY byte_offset"
        ).fetchall()
    assert counts == {
        "detector_run": 2,
        "candidate": 2,
        "candidate_evidence": 2,
        "candidate_signal": 2,
        "manual_task": 1,
        "manual_task_signal": 1,
    }
    assert tuple(candidate) == ("unknown-flag", 78.0)
    assert [(row[1], row[2], row[3]) for row in evidence] == [(15, 1, 1), (27, 1, 1)]


def test_unknown_detection_records_input_budget_skip(tmp_path) -> None:
    root, database = _project_with_body(tmp_path, b"x" * 20_000)

    summary = detect_unknown_candidates(root, max_evidence_bytes=100, max_total_bytes=100)

    assert summary.status == "partial"
    with database.connect() as connection:
        reason = connection.execute(
            "SELECT reason FROM detector_skip ORDER BY id DESC LIMIT 1"
        ).fetchone()[0]
    assert reason == "input-truncated"
