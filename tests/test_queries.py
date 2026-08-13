from datetime import datetime, timezone

import pytest

from auto_shark.core.ids import stable_id
from auto_shark.project import create_project
from auto_shark.queries import query_streams, query_transactions
from auto_shark.storage import BlobStore, Database


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def test_transaction_query_is_stable_bounded_and_filterable(tmp_path) -> None:
    capture = tmp_path / "capture.pcap"
    capture.write_bytes(b"capture")
    project = tmp_path / "sample.auto-shark"
    create_project(capture, project)
    database = Database(project / "project.sqlite")
    with database.connect() as connection:
        capture_id = int(connection.execute("SELECT id FROM capture").fetchone()[0])
        for frame in (10, 11, 12, 20, 21):
            connection.execute(
                "INSERT INTO frame (capture_id,frame_number) VALUES (?,?)", (capture_id, frame)
            )
        for request, response, uri in ((10, 11, "/a"), (20, 21, "/b")):
            request_id = stable_id("message", {"frame": request})
            response_id = stable_id("message", {"frame": response})
            connection.execute(
                "INSERT INTO protocol_message "
                "(message_id,capture_id,representative_frame,protocol,message_kind,fields_json) "
                "VALUES (?,?,?,'http','request','{}')",
                (request_id, capture_id, request),
            )
            request_db_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
            connection.execute(
                "INSERT INTO protocol_message "
                "(message_id,capture_id,representative_frame,protocol,message_kind,fields_json) "
                "VALUES (?,?,?,'http','response','{}')",
                (response_id, capture_id, response),
            )
            response_db_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
            connection.execute(
                "INSERT INTO http_message (protocol_message_id,method,uri,host) "
                "VALUES (?,'POST',?,'example.test')",
                (request_db_id, uri),
            )
            connection.execute(
                "INSERT INTO http_message (protocol_message_id,response_code,response_phrase) "
                "VALUES (?,200,'OK')",
                (response_db_id,),
            )
            transaction_id = stable_id("transaction", {"frame": request})
            connection.execute(
                "INSERT INTO transaction_record "
                "(transaction_id,capture_id,protocol,request_message_id,"
                "response_message_id,status) "
                "VALUES (?,?,'http',?,?,'matched')",
                (transaction_id, capture_id, request_db_id, response_db_id),
            )
            transaction_db_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
            connection.executemany(
                "INSERT INTO transaction_message "
                "(transaction_id,protocol_message_id,role,ordinal) VALUES (?,?,?,0)",
                (
                    (transaction_db_id, request_db_id, "request"),
                    (transaction_db_id, response_db_id, "response"),
                ),
            )
        first_transaction_id = int(
            connection.execute("SELECT id FROM transaction_record ORDER BY id LIMIT 1").fetchone()[
                0
            ]
        )
        first_request_id = int(
            connection.execute(
                "SELECT request_message_id FROM transaction_record WHERE id=?",
                (first_transaction_id,),
            ).fetchone()[0]
        )
        connection.execute(
            "INSERT INTO protocol_message "
            "(message_id,capture_id,representative_frame,protocol,message_kind,fields_json) "
            "VALUES ('extra-response',?,12,'http','response','{}')",
            (capture_id,),
        )
        extra_response_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
        connection.execute(
            "INSERT INTO http_message (protocol_message_id,response_code,response_phrase) "
            "VALUES (?,202,'Accepted')",
            (extra_response_id,),
        )
        connection.execute(
            "INSERT INTO transaction_message "
            "(transaction_id,protocol_message_id,role,ordinal) "
            "VALUES (?,?,'extra_response',1)",
            (first_transaction_id, extra_response_id),
        )
        connection.execute(
            "INSERT INTO tool_run (run_id,tool_name,argv_json,started_at,status) "
            "VALUES ('body-run','test','[]',?,'completed')",
            (_now(),),
        )
        tool_run_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
        connection.execute(
            "INSERT INTO http_body "
            "(protocol_message_id,tool_run_id,extracted_length,status,truncated,updated_at) "
            "VALUES (?,?,0,'absent',0,?)",
            (first_request_id, tool_run_id, _now()),
        )
        connection.execute(
            "INSERT INTO body_task "
            "(task_id,protocol_message_id,selection_reason,priority,max_bytes,status,"
            "extracted_bytes,created_at,updated_at) "
            "VALUES ('task',?,'test',1,100,'completed',0,?,?)",
            (first_request_id, _now(), _now()),
        )

    page = query_transactions(project, offset=1, limit=1)
    assert page.schema_version == "auto-shark.transactions/v1"
    assert page.total == 2 and page.count == 1
    assert page.items[0]["request"]["frame"] == 20
    filtered = query_transactions(project, uri="/a")
    assert filtered.total == 1
    assert filtered.items[0]["request"]["uri"] == "/a"
    assert filtered.items[0]["message_roles"] == {
        "extra_response": 1,
        "request": 1,
        "response": 1,
    }
    assert filtered.items[0]["body_states"] == {"absent": 1}
    assert filtered.items[0]["task_states"] == {"completed": 1}
    assert query_transactions(project, uri="/missing").items == ()
    empty_page = query_transactions(project, offset=99, limit=1)
    assert empty_page.total == 2 and empty_page.count == 0 and empty_page.items == ()
    with pytest.raises(ValueError, match="offset"):
        query_transactions(project, offset=-1)
    with pytest.raises(ValueError, match="between"):
        query_transactions(project, limit=1001)


def test_transaction_query_preserves_unmatched_and_orphan_shapes(tmp_path) -> None:
    capture = tmp_path / "capture.pcap"
    capture.write_bytes(b"capture")
    project = tmp_path / "sample.auto-shark"
    create_project(capture, project)
    database = Database(project / "project.sqlite")
    with database.connect() as connection:
        capture_id = int(connection.execute("SELECT id FROM capture").fetchone()[0])
        connection.executemany(
            "INSERT INTO frame (capture_id,frame_number) VALUES (?,?)",
            ((capture_id, 1), (capture_id, 2)),
        )
        connection.executemany(
            "INSERT INTO protocol_message "
            "(message_id,capture_id,representative_frame,protocol,message_kind,fields_json) "
            "VALUES (?,?,?,'http',?,'{}')",
            (
                ("request", capture_id, 1, "request"),
                ("response", capture_id, 2, "response"),
            ),
        )
        message_ids = {
            str(row["message_id"]): int(row["id"])
            for row in connection.execute("SELECT id,message_id FROM protocol_message")
        }
        connection.execute(
            "INSERT INTO http_message (protocol_message_id,method,uri) VALUES (?,'GET','/lost')",
            (message_ids["request"],),
        )
        connection.execute(
            "INSERT INTO http_message (protocol_message_id,response_code) VALUES (?,500)",
            (message_ids["response"],),
        )
        connection.execute(
            "INSERT INTO transaction_record "
            "(transaction_id,capture_id,protocol,request_message_id,status) "
            "VALUES ('unmatched',?,'http',?,'unmatched-request')",
            (capture_id, message_ids["request"]),
        )
        unmatched_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
        connection.execute(
            "INSERT INTO transaction_message "
            "(transaction_id,protocol_message_id,role,ordinal) VALUES (?,?,'request',0)",
            (unmatched_id, message_ids["request"]),
        )
        connection.execute(
            "INSERT INTO transaction_record "
            "(transaction_id,capture_id,protocol,response_message_id,status) "
            "VALUES ('orphan',?,'http',?,'orphan-response')",
            (capture_id, message_ids["response"]),
        )
        orphan_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
        connection.execute(
            "INSERT INTO transaction_message "
            "(transaction_id,protocol_message_id,role,ordinal) VALUES (?,?,'response',0)",
            (orphan_id, message_ids["response"]),
        )

    page = query_transactions(project)

    assert [item["status"] for item in page.items] == ["unmatched-request", "orphan-response"]
    assert page.items[0]["response"]["message_id"] is None
    assert page.items[1]["request"]["message_id"] is None
    assert page.items[1]["response"]["frame"] == 2


def test_stream_query_exposes_current_evidence_and_conflicts(tmp_path) -> None:
    capture = tmp_path / "capture.pcap"
    capture.write_bytes(b"capture")
    project = tmp_path / "sample.auto-shark"
    create_project(capture, project)
    database = Database(project / "project.sqlite")
    blob = BlobStore(project / "blobs").put_bytes(b"stream")
    with database.connect() as connection:
        capture_id = int(connection.execute("SELECT id FROM capture").fetchone()[0])
        connection.execute(
            "INSERT INTO conversation "
            "(conversation_id,capture_id,protocol,stream_index,endpoint_a,endpoint_b) "
            "VALUES ('conversation',?,'tcp',2,'a:1','b:2')",
            (capture_id,),
        )
        conversation_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
        connection.execute(
            "INSERT INTO tool_run (run_id,tool_name,argv_json,started_at,status) "
            "VALUES ('run','test','[]',?,'completed')",
            (_now(),),
        )
        tool_run_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
        connection.execute(
            "INSERT INTO tool_run (run_id,tool_name,argv_json,started_at,status) "
            "VALUES ('historical-run','test','[]',?,'completed')",
            (_now(),),
        )
        historical_run_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
        connection.execute(
            "INSERT INTO blob (sha256,byte_length,relative_path,complete,created_at) "
            "VALUES (?,?,?,?,?)",
            (blob.sha256, blob.byte_length, blob.path.relative_to(project).as_posix(), 1, _now()),
        )
        blob_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
        for frame in (3, 4):
            connection.execute(
                "INSERT INTO frame (capture_id,frame_number) VALUES (?,?)", (capture_id, frame)
            )
            connection.execute(
                "INSERT INTO tcp_segment "
                "(segment_id,capture_id,conversation_id,tool_run_id,frame_number,stream_index,"
                "direction,sequence_relative,sequence_raw,payload_length,payload_blob_id,"
                "retransmission,spurious_retransmission,out_of_order,lost_segment) "
                "VALUES (?,?,?,?,?,2,'a:1>b:2',1,1,6,?,0,0,0,0)",
                (f"segment-{frame}", capture_id, conversation_id, tool_run_id, frame, blob_id),
            )
            segment_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
            connection.execute(
                "INSERT INTO tcp_segment_run (segment_id,tool_run_id) VALUES (?,?)",
                (segment_id, tool_run_id),
            )
        segment_ids = [
            int(row[0])
            for row in connection.execute("SELECT id FROM tcp_segment ORDER BY frame_number")
        ]
        connection.execute(
            "INSERT INTO tcp_segment_run (segment_id,tool_run_id) VALUES (?,?)",
            (segment_ids[0], historical_run_id),
        )
        connection.execute(
            "INSERT INTO evidence "
            "(evidence_id,capture_id,source_kind,frame_start,frame_end,direction,"
            "byte_offset,byte_length,blob_id,locator_json) "
            "VALUES ('evidence',?,'tcp-stream',3,9,'a:1>b:2',0,6,?,'{}')",
            (capture_id, blob_id),
        )
        evidence_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
        connection.execute(
            "INSERT INTO tcp_reconstruction "
            "(reconstruction_id,conversation_id,direction,evidence_id,tool_run_id,status,"
            "sequence_start,sequence_end,unique_bytes,output_bytes,duplicate_bytes,"
            "conflict_bytes,gap_bytes,capture_midstream,max_output_bytes,updated_at) "
            "VALUES ('reconstruction',?,'a:1>b:2',?,?,'conflicting',1,7,6,6,2,1,0,0,100,?)",
            (conversation_id, evidence_id, tool_run_id, _now()),
        )
        reconstruction_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
        connection.executemany(
            "INSERT INTO tcp_reconstruction_source "
            "(reconstruction_id,segment_id,sequence_offset,output_offset,byte_length,role) "
            "VALUES (?,?,?,?,?,'primary')",
            (
                (reconstruction_id, segment_ids[0], 1, 0, 3),
                (reconstruction_id, segment_ids[1], 4, 3, 3),
            ),
        )
        connection.execute(
            "INSERT INTO tcp_overlap_conflict "
            "(conflict_id,reconstruction_id,first_segment_id,conflicting_segment_id,"
            "sequence_start,byte_length,first_sha256,conflicting_sha256) "
            "VALUES ('conflict',?,?,?,?,1,'a','b')",
            (reconstruction_id, segment_ids[0], segment_ids[1], 4),
        )

    page = query_streams(project)
    assert page.schema_version == "auto-shark.streams/v1"
    assert page.total == page.count == 1
    item = page.items[0]
    assert item["stream_index"] == 2
    assert item["status"] == "conflicting"
    assert item["counts"]["segments"] == 2
    assert item["counts"]["conflicts"] == 1
    assert item["evidence"] == {
        "evidence_id": "evidence",
        "frame_start": 3,
        "frame_end": 4,
        "recorded_frame_start": 3,
        "recorded_frame_end": 9,
        "blob_sha256": blob.sha256,
        "byte_length": 6,
    }
