import json

import pytest

import auto_shark.webshell_detection as webshell_detection
from auto_shark.core.ids import stable_id
from auto_shark.m4_queries import query_findings, query_timeline
from auto_shark.project import create_project
from auto_shark.storage import BlobStore, Database
from auto_shark.webshell_detection import (
    classify_webshell_action,
    detect_webshell_activity,
    normalize_webshell_target,
    wrapper_action_parameter,
)

WRAPPER = "@eval\x01(base64_decode($_POST[action]));"
SYSTEM_ACTION = "php_uname(); get_current_user(); posix_geteuid();"
LIST_ACTION = '$D=base64_decode($_POST["z1"]); opendir($D); readdir($F);'
WRITE_ACTION = (
    '$f=base64_decode($_POST["z1"]);$c=$_POST["z2"];'
    'fwrite(fopen($f,"w"),$c);'
)


def _insert_evidence(connection, store, capture_id, message_id, frame, label, data):
    blob = store.put_bytes(data)
    connection.execute(
        "INSERT OR IGNORE INTO blob(sha256,byte_length,relative_path,complete,created_at) "
        "VALUES(?,?,?,1,datetime('now'))",
        (blob.sha256, len(data), blob.path.relative_to(store.root.parent).as_posix()),
    )
    blob_id = int(
        connection.execute("SELECT id FROM blob WHERE sha256=?", (blob.sha256,)).fetchone()[0]
    )
    public_id = stable_id("test-evidence", {"frame": frame, "label": label})
    text = data.decode("utf-8") if b"\x00" not in data and b"\xff" not in data else None
    connection.execute(
        "INSERT INTO evidence(evidence_id,capture_id,source_kind,frame_start,frame_end,"
        "protocol_message_id,byte_length,field_name,text_value,blob_id,locator_json) "
        "VALUES(?,?,'transform-output',?,?,?,?,?,?,?,'{}')",
        (public_id, capture_id, frame, frame, message_id, len(data), label, text, blob_id),
    )
    return int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])


def _add_field(
    connection,
    store,
    capture_id,
    message_id,
    frame,
    ordinal,
    name,
    decoded,
    output=None,
    transform="base64",
):
    decoded_id = _insert_evidence(
        connection, store, capture_id, message_id, frame, f"{name}-decoded", decoded
    )
    connection.execute(
        "INSERT INTO form_field(protocol_message_id,ordinal,name,raw_value_evidence_id,"
        "decoded_value_evidence_id) VALUES(?,?,?,?,?)",
        (message_id, ordinal, name, decoded_id, decoded_id),
    )
    if output is not None:
        output_id = _insert_evidence(
            connection, store, capture_id, message_id, frame, f"{name}-output", output
        )
        connection.execute(
            "INSERT INTO transform(transform_id,parent_evidence_id,output_evidence_id,name,"
            "version,parameters_json,depth,status,truncated) "
            "VALUES(?,?,?,?,1,'{}',1,'complete',0)",
            (
                stable_id("test-transform", {"frame": frame, "name": name}),
                decoded_id,
                output_id,
                transform,
            ),
        )


def _project(tmp_path, operations):
    capture = tmp_path / "capture.pcap"
    capture.write_bytes(b"pcap")
    root = tmp_path / "webshell.auto-shark"
    create_project(capture, root, allow_synced=True)
    database = Database(root / "project.sqlite")
    store = BlobStore(root / "blobs")
    with database.connect() as connection:
        capture_id = int(connection.execute("SELECT id FROM capture").fetchone()[0])
        for index, operation in enumerate(operations):
            frame = index * 2 + 1
            response_frame = frame + 1
            connection.executemany(
                "INSERT INTO frame(capture_id,frame_number) VALUES(?,?)",
                ((capture_id, frame), (capture_id, response_frame)),
            )
            connection.execute(
                "INSERT INTO protocol_message(message_id,capture_id,representative_frame,"
                "protocol,message_kind,fields_json) VALUES(?,?,?,'http','request','{}')",
                (f"request-{frame}", capture_id, frame),
            )
            request_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
            connection.execute(
                "INSERT INTO protocol_message(message_id,capture_id,representative_frame,"
                "protocol,message_kind,fields_json) VALUES(?,?,?,'http','response','{}')",
                (f"response-{response_frame}", capture_id, response_frame),
            )
            response_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
            connection.execute(
                "INSERT INTO http_message(protocol_message_id,method,uri) "
                "VALUES(?,'POST','/shell.php')",
                (request_id,),
            )
            connection.execute(
                "INSERT INTO http_message(protocol_message_id,response_code) VALUES(?,200)",
                (response_id,),
            )
            connection.execute(
                "INSERT INTO transaction_record(transaction_id,capture_id,protocol,"
                "request_message_id,response_message_id,status) "
                "VALUES(?,?,'http',?,?,'matched')",
                (f"transaction-{frame}", capture_id, request_id, response_id),
            )
            _add_field(
                connection,
                store,
                capture_id,
                request_id,
                frame,
                0,
                "aa",
                WRAPPER.encode(),
            )
            _add_field(
                connection,
                store,
                capture_id,
                request_id,
                frame,
                1,
                "action",
                b"encoded-action",
                (
                    operation.get("action", "").encode()
                    if operation.get("action_output", True)
                    else None
                ),
            )
            if operation.get("target") is not None:
                _add_field(
                    connection,
                    store,
                    capture_id,
                    request_id,
                    frame,
                    2,
                    "z1",
                    b"encoded-target",
                    operation["target"].encode(),
                )
            if operation.get("payload") is not None:
                _add_field(
                    connection,
                    store,
                    capture_id,
                    request_id,
                    frame,
                    3,
                    "z2",
                    b"encoded-payload",
                    operation["payload"],
                    transform="hex",
                )
    return root, database


def test_webshell_static_classifier_covers_supported_api_shapes() -> None:
    cases = {
        "system-information": SYSTEM_ACTION,
        "directory-listing": LIST_ACTION,
        "file-write": WRITE_ACTION,
        "file-read": 'fread(fopen(base64_decode($_POST["z1"]),"r"),filesize($F));',
        "file-delete": 'unlink(base64_decode($_POST["z1"]));',
        "file-rename": 'rename(base64_decode($_POST["z1"]),$new);',
        "directory-create": 'mkdir(base64_decode($_POST["z1"]));',
        "command-execution": 'system(base64_decode($_POST["z1"]));',
        "database-action": 'mysqli_query($db,$_POST["z1"]);',
    }
    assert wrapper_action_parameter(WRAPPER) == "action"
    assert {
        name: classify_webshell_action(action).event_kind for name, action in cases.items()
    } == {name: name for name in cases}
    assert classify_webshell_action("echo 'plain';").event_kind == "unknown-operation"
    assert normalize_webshell_target("d:/web/root/") == "D:\\web\\root"
    assert normalize_webshell_target("/var/www/../tmp/") == "/var/tmp"


def test_webshell_detection_persists_timeline_payload_and_semantic_duplicates(tmp_path) -> None:
    root, database = _project(
        tmp_path,
        [
            {"action": SYSTEM_ACTION},
            {"action": LIST_ACTION, "target": r"D:\web\root"},
            {"action": LIST_ACTION, "target": "D:\\web\\root\\"},
            {"action": WRITE_ACTION, "target": r"D:\web\root\a.bin", "payload": b"\x00\xff"},
        ],
    )

    first = detect_webshell_activity(root, max_preview_bytes=16)
    second = detect_webshell_activity(root, max_preview_bytes=16)

    assert first.events == second.events == 4
    assert first.findings == second.findings == 1
    assert first.status == second.status == "completed"
    with database.connect() as connection:
        events = connection.execute(
            "SELECT event_kind,request_frame,target,duplicate_of,detail_json "
            "FROM behavior_event ORDER BY request_frame"
        ).fetchall()
        roles = {
            row[0]: row[1]
            for row in connection.execute(
                "SELECT role,count(*) FROM behavior_event_evidence GROUP BY role"
            )
        }
        event_runs = int(
            connection.execute("SELECT count(*) FROM behavior_event_run").fetchone()[0]
        )
        finding_runs = int(connection.execute("SELECT count(*) FROM finding_run").fetchone()[0])
    assert [row[0] for row in events] == [
        "system-information",
        "directory-listing",
        "directory-listing",
        "file-write",
    ]
    assert events[2][3] is not None
    assert sum(row[3] is None for row in events) == 3
    assert len(json.loads(events[0][4])["preview"].encode()) <= 16
    assert roles == {"operation": 4, "payload": 1, "target": 3, "wrapper": 4}
    assert event_runs == 8 and finding_runs == 2

    timeline = query_timeline(root, max_evidence_links=2, max_detail_bytes=5)
    expanded = query_timeline(
        root,
        include_duplicates=True,
        event_kind="directory-listing",
        detector="static-webshell-activity",
    )
    findings = query_findings(root, max_evidence_links=2, max_detail_bytes=5)
    assert timeline.total == timeline.count == 3
    assert expanded.total == expanded.count == 2
    assert findings.candidate_total == 0
    assert findings.finding_total == 1
    assert timeline.items[0]["detail_truncated"]
    assert timeline.evidence_links_returned == 2
    assert findings.evidence_links_returned == 2
    assert findings.findings[0]["evidence_truncated"]


def test_webshell_detection_records_missing_action_and_event_budget(tmp_path) -> None:
    root, database = _project(
        tmp_path,
        [
            {"action": LIST_ACTION, "action_output": False, "target": r"D:\web"},
            {"action": SYSTEM_ACTION},
        ],
    )

    result = detect_webshell_activity(root, max_events=1)

    assert result.status == "partial"
    assert result.events == 1
    assert result.inputs_skipped == 2
    with database.connect() as connection:
        event = connection.execute("SELECT event_kind,status FROM behavior_event").fetchone()
        reasons = {
            row[0] for row in connection.execute("SELECT reason FROM detector_skip")
        }
    assert tuple(event) == ("unknown-operation", "partial")
    assert reasons == {"missing-action-transform", "event-limit"}


def test_webshell_detection_marks_failed_runs(monkeypatch, tmp_path) -> None:
    root, database = _project(tmp_path, [{"action": SYSTEM_ACTION}])

    def fail_rows(*args, **kwargs):
        raise RuntimeError("synthetic WebShell failure")

    monkeypatch.setattr(webshell_detection, "_transaction_rows", fail_rows)
    with pytest.raises(RuntimeError, match="synthetic WebShell failure"):
        detect_webshell_activity(root)

    with database.connect() as connection:
        detector = connection.execute(
            "SELECT status,inputs_skipped,ended_at FROM detector_run ORDER BY id DESC LIMIT 1"
        ).fetchone()
        tool = connection.execute(
            "SELECT status,exit_code,stderr_text,ended_at FROM tool_run ORDER BY id DESC LIMIT 1"
        ).fetchone()
    assert tuple(detector[:2]) == ("failed", 1) and detector[2] is not None
    assert tuple(tool[:2]) == ("failed", 1)
    assert "synthetic WebShell failure" in tool[2] and tool[3] is not None
