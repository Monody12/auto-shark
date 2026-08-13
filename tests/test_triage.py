import json
from datetime import datetime, timezone

from auto_shark.core.ids import EvidenceLocator, evidence_id
from auto_shark.pipeline import scan_project
from auto_shark.project import create_project
from auto_shark.storage import BlobStore, Database
from auto_shark.triage import triage_project


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _project(tmp_path):
    capture = tmp_path / "capture.pcap"
    capture.write_bytes(b"capture")
    root = tmp_path / "sample.auto-shark"
    info = create_project(capture, root)
    return root, info, Database(root / "project.sqlite")


def _blob(database, root, data: bytes) -> int:
    blob = BlobStore(root / "blobs").put_bytes(data)
    with database.connect() as connection:
        connection.execute(
            "INSERT OR IGNORE INTO blob "
            "(sha256,byte_length,relative_path,complete,created_at) VALUES (?,?,?,?,?)",
            (blob.sha256, blob.byte_length, blob.path.relative_to(root).as_posix(), 1, _now()),
        )
        return int(
            connection.execute("SELECT id FROM blob WHERE sha256=?", (blob.sha256,)).fetchone()[0]
        )


def test_triage_ranks_password_above_form_context_idempotently(tmp_path) -> None:
    root, info, database = _project(tmp_path)
    body = b"email=user&password=0123456789abcdef0123456789abcdef&captcha=ABCD"
    blob_id = _blob(database, root, body)
    locator = EvidenceLocator(
        capture_sha256=info.capture_sha256,
        source_kind="http-body",
        frame_start=20,
        frame_end=20,
        protocol_message="request-20",
        byte_length=len(body),
    )
    with database.connect() as connection:
        capture_id = int(connection.execute("SELECT id FROM capture").fetchone()[0])
        connection.execute(
            "INSERT INTO frame (capture_id,frame_number) VALUES (?,20)", (capture_id,)
        )
        connection.execute(
            "INSERT INTO protocol_message "
            "(message_id,capture_id,representative_frame,protocol,message_kind,fields_json) "
            "VALUES ('request-20',?,20,'http','request','{}')",
            (capture_id,),
        )
        message_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
        connection.execute(
            "INSERT INTO http_message (protocol_message_id,content_length,content_type) "
            "VALUES (?,?,'application/x-www-form-urlencoded')",
            (message_id, len(body)),
        )
        connection.execute(
            "INSERT INTO tool_run (run_id,tool_name,argv_json,started_at,status) "
            "VALUES ('body-run','test','[]',?,'completed')",
            (_now(),),
        )
        run_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
        connection.execute(
            "INSERT INTO evidence "
            "(evidence_id,capture_id,source_kind,frame_start,frame_end,protocol_message_id,"
            "byte_length,blob_id,locator_json) VALUES (?,?,'http-body',20,20,?,?,?,'{}')",
            (evidence_id(locator), capture_id, message_id, len(body), blob_id),
        )
        body_evidence_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
        connection.execute(
            "INSERT INTO http_body "
            "(protocol_message_id,evidence_id,tool_run_id,declared_length,extracted_length,"
            "status,truncated,updated_at) VALUES (?,?,?,?,?,'complete',0,?)",
            (message_id, body_evidence_id, run_id, len(body), len(body), _now()),
        )
    scan_project(root)

    first = triage_project(root, window_bytes=7)
    second = triage_project(root, window_bytes=7)

    assert first == second
    assert first.field_candidates == 3
    assert [item.kind for item in first.candidates] == [
        "sensitive-field",
        "context-field",
        "context-field",
    ]
    assert first.candidates[0].value == "0123456789abcdef0123456789abcdef"
    assert first.candidates[0].rank_score > first.candidates[1].rank_score
    with database.connect() as connection:
        counts = {
            table: int(connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0])
            for table in ("triage_scan", "candidate", "candidate_evidence", "candidate_signal")
        }
        password_signals = {
            str(row[0]): float(row[1])
            for row in connection.execute(
                "SELECT cs.signal_name,cs.contribution FROM candidate_signal cs "
                "JOIN candidate c ON c.id=cs.candidate_id WHERE c.kind='sensitive-field'"
            )
        }
    assert counts == {
        "triage_scan": 5,
        "candidate": 3,
        "candidate_evidence": 3,
        "candidate_signal": 12,
    }
    assert password_signals["field-role"] == 60.0
    assert password_signals["value-shape"] == 8.0


def test_triage_maps_tcp_match_to_primary_frame_and_ignores_history(tmp_path) -> None:
    root, _, database = _project(tmp_path)
    current = b"xxflag{tcp-current}yy"
    historical = b"flag{tcp-history}"
    current_blob_id = _blob(database, root, current)
    historical_blob_id = _blob(database, root, historical)
    segment_blob_id = _blob(database, root, b"flag{tcp-current}")
    with database.connect() as connection:
        capture_id = int(connection.execute("SELECT id FROM capture").fetchone()[0])
        connection.executemany(
            "INSERT INTO frame (capture_id,frame_number) VALUES (?,?)",
            ((capture_id, 40), (capture_id, 41), (capture_id, 42)),
        )
        connection.execute(
            "INSERT INTO conversation "
            "(conversation_id,capture_id,protocol,stream_index,endpoint_a,endpoint_b) "
            "VALUES ('tcp-conversation',?,'tcp',0,'client:1','server:23')",
            (capture_id,),
        )
        conversation_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
        connection.execute(
            "INSERT INTO tool_run (run_id,tool_name,argv_json,started_at,status) "
            "VALUES ('tcp-run','test','[]',?,'completed')",
            (_now(),),
        )
        run_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
        for frame, sequence, length, blob_id in (
            (40, 1, 2, current_blob_id),
            (41, 3, len(b"flag{tcp-current}"), segment_blob_id),
            (42, 20, 2, current_blob_id),
        ):
            connection.execute(
                "INSERT INTO tcp_segment "
                "(segment_id,capture_id,conversation_id,tool_run_id,frame_number,stream_index,"
                "direction,sequence_relative,sequence_raw,payload_length,payload_blob_id,"
                "retransmission,spurious_retransmission,out_of_order,lost_segment) "
                "VALUES (?,?,?,?,?,0,'client:1>server:23',?,?,?, ?,0,0,0,0)",
                (
                    f"segment-{frame}",
                    capture_id,
                    conversation_id,
                    run_id,
                    frame,
                    sequence,
                    sequence,
                    length,
                    blob_id,
                ),
            )
            segment_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
            connection.execute(
                "INSERT INTO tcp_segment_run (segment_id,tool_run_id) VALUES (?,?)",
                (segment_id, run_id),
            )
        segment_ids = {
            int(row["frame_number"]): int(row["id"])
            for row in connection.execute("SELECT id,frame_number FROM tcp_segment")
        }
        connection.execute(
            "INSERT INTO evidence "
            "(evidence_id,capture_id,source_kind,frame_start,frame_end,direction,byte_offset,"
            "byte_length,blob_id,locator_json) "
            "VALUES ('history',?,'tcp-stream',1,2,'client:1>server:23',0,?,?, '{}')",
            (capture_id, len(historical), historical_blob_id),
        )
        connection.execute(
            "INSERT INTO evidence "
            "(evidence_id,capture_id,source_kind,frame_start,frame_end,direction,byte_offset,"
            "byte_length,blob_id,locator_json) "
            "VALUES ('current',?,'tcp-stream',40,42,'client:1>server:23',0,?,?, '{}')",
            (capture_id, len(current), current_blob_id),
        )
        current_evidence_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
        connection.execute(
            "INSERT INTO tcp_reconstruction "
            "(reconstruction_id,conversation_id,direction,evidence_id,tool_run_id,status,"
            "sequence_start,sequence_end,unique_bytes,output_bytes,duplicate_bytes,"
            "conflict_bytes,gap_bytes,capture_midstream,max_output_bytes,updated_at) "
            "VALUES ('current-reconstruction',?,'client:1>server:23',?,?,'complete',"
            "1,22,?,?,0,0,0,0,100,?)",
            (conversation_id, current_evidence_id, run_id, len(current), len(current), _now()),
        )
        reconstruction_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
        connection.executemany(
            "INSERT INTO tcp_reconstruction_source "
            "(reconstruction_id,segment_id,sequence_offset,output_offset,byte_length,role) "
            "VALUES (?,?,?,?,?,'primary')",
            (
                (reconstruction_id, segment_ids[40], 1, 0, 2),
                (
                    reconstruction_id,
                    segment_ids[41],
                    3,
                    2,
                    len(b"flag{tcp-current}"),
                ),
                (reconstruction_id, segment_ids[42], 20, len(current) - 2, 2),
            ),
        )

    summary = triage_project(root, window_bytes=5)

    assert summary.evidence_selected == summary.evidence_scanned == 1
    assert [item.value for item in summary.candidates] == ["flag{tcp-current}"]
    with database.connect() as connection:
        match = connection.execute(
            "SELECT e.frame_start,e.frame_end,e.byte_offset,e.byte_length,e.blob_id "
            "FROM candidate_evidence ce JOIN evidence e ON e.id=ce.evidence_id"
        ).fetchone()
        detail = json.loads(
            connection.execute(
                "SELECT detail_json FROM candidate_signal WHERE signal_name='known-format'"
            ).fetchone()[0]
        )
    assert tuple(match) == (41, 41, 2, len(b"flag{tcp-current}"), current_blob_id)
    assert detail["contributing_frames"] == [41]


def test_triage_scans_artifact_blob_in_artifact_coordinates(tmp_path) -> None:
    root, _, database = _project(tmp_path)
    parent = b"prefixflag{artifact}tail"
    artifact = b"flag{artifact}"
    parent_blob_id = _blob(database, root, parent)
    artifact_blob_id = _blob(database, root, artifact)
    with database.connect() as connection:
        capture_id = int(connection.execute("SELECT id FROM capture").fetchone()[0])
        connection.execute(
            "INSERT INTO frame (capture_id,frame_number) VALUES (?,233)", (capture_id,)
        )
        connection.execute(
            "INSERT INTO evidence "
            "(evidence_id,capture_id,source_kind,frame_start,frame_end,byte_offset,byte_length,"
            "blob_id,locator_json) VALUES ('parent',?,'source',233,233,0,?,?, '{}')",
            (capture_id, len(parent), parent_blob_id),
        )
        parent_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
        connection.execute(
            "INSERT INTO evidence "
            "(evidence_id,capture_id,source_kind,frame_start,frame_end,byte_offset,byte_length,"
            "blob_id,locator_json) VALUES ('carved',?,'file-carve',233,233,6,?,?, '{}')",
            (capture_id, len(artifact), parent_blob_id),
        )
        carved_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
        connection.execute(
            "INSERT INTO artifact "
            "(artifact_id,blob_id,source_evidence_id,review_state,created_at) "
            "VALUES ('artifact',?,?,'unreviewed',?)",
            (artifact_blob_id, carved_id, _now()),
        )
        artifact_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
        connection.execute(
            "INSERT INTO file_carve "
            "(carve_id,parent_evidence_id,carved_evidence_id,artifact_id,format,start_offset,"
            "byte_length,structural_status,validation_detail,created_at) "
            "VALUES ('carve',?,?,?,'test',6,?,'validated','test',?)",
            (parent_id, carved_id, artifact_id, len(artifact), _now()),
        )

    summary = triage_project(root, window_bytes=4)

    assert [item.value for item in summary.candidates] == ["flag{artifact}"]
    with database.connect() as connection:
        match = connection.execute(
            "SELECT e.byte_offset,e.byte_length,e.blob_id FROM candidate_evidence ce "
            "JOIN evidence e ON e.id=ce.evidence_id"
        ).fetchone()
    assert tuple(match) == (0, len(artifact), artifact_blob_id)


def test_triage_persists_budget_and_evidence_limit_skips(tmp_path) -> None:
    root, _, database = _project(tmp_path)
    first_blob_id = _blob(database, root, b"1234567890")
    second_blob_id = _blob(database, root, b"abcdefghij")
    with database.connect() as connection:
        capture_id = int(connection.execute("SELECT id FROM capture").fetchone()[0])
        connection.executemany(
            "INSERT INTO frame (capture_id,frame_number) VALUES (?,?)",
            ((capture_id, 1), (capture_id, 2)),
        )
        connection.executemany(
            "INSERT INTO protocol_message "
            "(message_id,capture_id,representative_frame,protocol,message_kind,fields_json) "
            "VALUES (?,?,?,'http','request','{}')",
            (("one", capture_id, 1), ("two", capture_id, 2)),
        )
        message_ids = {
            str(row["message_id"]): int(row["id"])
            for row in connection.execute("SELECT id,message_id FROM protocol_message")
        }
        connection.execute(
            "INSERT INTO tool_run (run_id,tool_name,argv_json,started_at,status) "
            "VALUES ('run','test','[]',?,'completed')",
            (_now(),),
        )
        run_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
        for public_id, frame, message, blob_id in (
            ("a", 1, "one", first_blob_id),
            ("b", 2, "two", second_blob_id),
        ):
            connection.execute(
                "INSERT INTO http_message (protocol_message_id) VALUES (?)",
                (message_ids[message],),
            )
            connection.execute(
                "INSERT INTO evidence "
                "(evidence_id,capture_id,source_kind,frame_start,frame_end,protocol_message_id,"
                "byte_length,blob_id,locator_json) VALUES (?,?,'http-body',?,?,?,10,?,'{}')",
                (public_id, capture_id, frame, frame, message_ids[message], blob_id),
            )
            evidence_db_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
            connection.execute(
                "INSERT INTO http_body "
                "(protocol_message_id,evidence_id,tool_run_id,extracted_length,status,truncated,"
                "updated_at) VALUES (?,?,?,10,'complete',0,?)",
                (message_ids[message], evidence_db_id, run_id, _now()),
            )

    budget = triage_project(root, max_total_bytes=10)
    limited = triage_project(root, max_evidence=1)

    assert budget.complete == 1 and budget.skipped_budget == 1
    assert limited.complete == 1 and limited.skipped_limit == 1
    with database.connect() as connection:
        assert connection.execute("SELECT count(*) FROM triage_scan").fetchone()[0] == 4
        assert (
            connection.execute("SELECT count(DISTINCT policy_json) FROM triage_scan").fetchone()[0]
            == 2
        )


def test_triage_records_truncation_candidate_limit_and_missing_blob(tmp_path) -> None:
    root, _, database = _project(tmp_path)
    limited_blob_id = _blob(database, root, b"flag{one}--flag{two}--tail")
    missing_blob_id = _blob(database, root, b"missing")
    with database.connect() as connection:
        capture_id = int(connection.execute("SELECT id FROM capture").fetchone()[0])
        connection.executemany(
            "INSERT INTO frame (capture_id,frame_number) VALUES (?,?)",
            ((capture_id, 1), (capture_id, 2)),
        )
        connection.executemany(
            "INSERT INTO protocol_message "
            "(message_id,capture_id,representative_frame,protocol,message_kind,fields_json) "
            "VALUES (?,?,?,'http','request','{}')",
            (("limited", capture_id, 1), ("missing", capture_id, 2)),
        )
        message_ids = {
            str(row["message_id"]): int(row["id"])
            for row in connection.execute("SELECT id,message_id FROM protocol_message")
        }
        connection.execute(
            "INSERT INTO tool_run (run_id,tool_name,argv_json,started_at,status) "
            "VALUES ('run','test','[]',?,'completed')",
            (_now(),),
        )
        run_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
        for public_id, frame, message, length, blob_id in (
            ("a-limited", 1, "limited", 28, limited_blob_id),
            ("z-missing", 2, "missing", 7, missing_blob_id),
        ):
            connection.execute(
                "INSERT INTO http_message (protocol_message_id) VALUES (?)",
                (message_ids[message],),
            )
            connection.execute(
                "INSERT INTO evidence "
                "(evidence_id,capture_id,source_kind,frame_start,frame_end,protocol_message_id,"
                "byte_length,blob_id,locator_json) VALUES (?,?,'http-body',?,?,?, ?,?,'{}')",
                (public_id, capture_id, frame, frame, message_ids[message], length, blob_id),
            )
            evidence_db_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
            connection.execute(
                "INSERT INTO http_body "
                "(protocol_message_id,evidence_id,tool_run_id,extracted_length,status,truncated,"
                "updated_at) VALUES (?,?,?,?,'complete',0,?)",
                (message_ids[message], evidence_db_id, run_id, length, _now()),
            )
        missing_path = connection.execute(
            "SELECT relative_path FROM blob WHERE id=?", (missing_blob_id,)
        ).fetchone()[0]
    (root / str(missing_path)).unlink()

    candidate_limited = triage_project(root, max_matches_per_evidence=1)
    truncated = triage_project(root, max_evidence_bytes=5, max_matches_per_evidence=10)

    assert candidate_limited.candidate_limited == 1
    assert candidate_limited.failed == 1
    assert truncated.input_truncated == 1
    assert truncated.failed == 1
    with database.connect() as connection:
        failed = connection.execute(
            "SELECT error FROM triage_scan WHERE status='failed' ORDER BY updated_at DESC LIMIT 1"
        ).fetchone()[0]
    assert "blobs" in str(failed) and "sha256" in str(failed)


def test_triage_rejects_placeholders_and_nonpositive_limits(tmp_path) -> None:
    root, _, database = _project(tmp_path)
    body = b"password=changeme&email=user"
    blob_id = _blob(database, root, body)
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
        message_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
        connection.execute(
            "INSERT INTO http_message (protocol_message_id,content_type) "
            "VALUES (?,'application/x-www-form-urlencoded')",
            (message_id,),
        )
        connection.execute(
            "INSERT INTO tool_run (run_id,tool_name,argv_json,started_at,status) "
            "VALUES ('run','test','[]',?,'completed')",
            (_now(),),
        )
        run_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
        connection.execute(
            "INSERT INTO evidence "
            "(evidence_id,capture_id,source_kind,frame_start,frame_end,protocol_message_id,"
            "byte_length,blob_id,locator_json) VALUES ('body',?,'http-body',1,1,?,?,?,'{}')",
            (capture_id, message_id, len(body), blob_id),
        )
        evidence_db_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
        connection.execute(
            "INSERT INTO http_body "
            "(protocol_message_id,evidence_id,tool_run_id,extracted_length,status,truncated,"
            "updated_at) VALUES (?,?,?,?,'complete',0,?)",
            (message_id, evidence_db_id, run_id, len(body), _now()),
        )
    scan_project(root)

    summary = triage_project(root)

    assert [(item.kind, item.value) for item in summary.candidates] == [("context-field", "user")]
    import pytest

    with pytest.raises(ValueError, match="positive"):
        triage_project(root, max_total_bytes=0)
