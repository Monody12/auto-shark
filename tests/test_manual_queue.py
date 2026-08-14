from datetime import datetime, timezone

from auto_shark.core.ids import candidate_id
from auto_shark.manual_queue import rebuild_manual_queue, update_manual_task_state
from auto_shark.project import create_project
from auto_shark.queries import query_manual_queue, query_summary
from auto_shark.storage import Database


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _fixture(tmp_path):
    capture = tmp_path / "capture.pcap"
    capture.write_bytes(b"pcap")
    root = tmp_path / "case.auto-shark"
    info = create_project(capture, root, allow_synced=True)
    database = Database(root / "project.sqlite")
    with database.connect() as connection:
        capture_id = int(connection.execute("SELECT id FROM capture").fetchone()[0])
        connection.execute(
            "INSERT INTO frame(capture_id,frame_number) VALUES(?,1)", (capture_id,)
        )
        connection.execute(
            "INSERT INTO evidence "
            "(evidence_id,capture_id,source_kind,frame_start,frame_end,"
            "byte_offset,byte_length,locator_json) "
            "VALUES('evidence',?,'flag-match',1,1,0,4,'{}')",
            (capture_id,),
        )
        evidence_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
        public_candidate = candidate_id("flag", "flag")
        connection.execute(
            "INSERT INTO candidate "
            "(candidate_id,kind,raw_value,normalized_value,confidence,rank_score,created_at) "
            "VALUES(?,'flag','flag','flag',1,100,?)",
            (public_candidate, _now()),
        )
        candidate_db_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
        connection.execute(
            "INSERT INTO candidate_evidence(candidate_id,evidence_id,role) "
            "VALUES(?,?,'match')",
            (candidate_db_id, evidence_id),
        )
        connection.execute(
            "INSERT INTO finding "
            "(finding_id,detector,detector_version,title,description,severity,"
            "confidence,created_at) VALUES"
            "('finding','http-status-body-contradiction','1','title','desc','high',1,?)",
            (_now(),),
        )
        finding_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
        connection.execute(
            "INSERT INTO finding_evidence(finding_id,evidence_id,role) "
            "VALUES(?,?,'success-semantic')",
            (finding_id, evidence_id),
        )
        connection.execute(
            "INSERT INTO blob(sha256,byte_length,relative_path,media_type,complete,created_at) "
            "VALUES(?,4,'blobs/artifact','application/x-rar',1,?)",
            ("a" * 64, _now()),
        )
        blob_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
        connection.execute(
            "INSERT INTO artifact "
            "(artifact_id,blob_id,source_evidence_id,suggested_name,"
            "detected_media_type,review_state,created_at) "
            "VALUES('artifact',?,?, 'flag.rar','application/x-rar','unreviewed',?)",
            (blob_id, evidence_id, _now()),
        )
        connection.execute(
            "INSERT INTO review_mark(subject_kind,subject_id,state,updated_at) "
            "VALUES('artifact','artifact','key_evidence',?)",
            (_now(),),
        )
        connection.execute(
            "INSERT INTO note(subject_kind,subject_id,body,created_at,updated_at) "
            "VALUES('artifact','artifact','keep',?,?)",
            (_now(), _now()),
        )
        connection.execute(
            "INSERT INTO tool_run(run_id,tool_name,argv_json,started_at,status) "
            "VALUES('inventory-tool','test','[]',?,'completed')",
            (_now(),),
        )
        tool_run_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
        connection.execute(
            "INSERT INTO capture_inventory_run "
            "(inventory_run_id,capture_id,tool_run_id,policy_json,status,"
            "processed_frames,skipped_frames,skipped_conversations,"
            "skipped_protocol_labels,started_at,ended_at) "
            "VALUES('inventory',?,?,'{}','completed',1,0,0,0,?,?)",
            (capture_id, tool_run_id, _now(), _now()),
        )
        inventory_run_id = int(
            connection.execute("SELECT last_insert_rowid()").fetchone()[0]
        )
        connection.execute(
            "INSERT INTO protocol_observation "
            "(observation_id,capture_id,protocol_label,frame_count,first_frame,last_frame,"
            "inventory_run_id,updated_at) VALUES('unknown',?,'oicq',50,1,1,?,?)",
            (capture_id, inventory_run_id, _now()),
        )
        connection.execute(
            "INSERT INTO analysis_coverage "
            "(coverage_id,capture_id,subject_kind,subject_id,status,detail_json,updated_at) "
            "VALUES('coverage',?,'protocol','unknown','unavailable','{}',?)",
            (capture_id, _now()),
        )
    return root, database, info


def test_queue_rebuild_is_idempotent_and_preserves_manual_state(tmp_path) -> None:
    root, database, _ = _fixture(tmp_path)
    first = rebuild_manual_queue(root)
    assert first.created == first.tasks == 4
    assert first.signals == 4
    page = query_manual_queue(root, limit=10)
    assert [item["suggested_priority"] for item in page.items] == [100, 90, 80, 40]
    candidate_task = page.items[0]["task_id"]
    update_manual_task_state(root, candidate_task, "in-progress")
    with database.connect() as connection:
        connection.execute(
            "UPDATE artifact SET review_state='reviewed' WHERE artifact_id='artifact'"
        )
    second = rebuild_manual_queue(root)
    assert second.created == 0
    with database.connect() as connection:
        state = connection.execute(
            "SELECT state FROM manual_task WHERE task_id=?", (candidate_task,)
        ).fetchone()[0]
        review = connection.execute(
            "SELECT state FROM review_mark WHERE subject_id='artifact'"
        ).fetchone()[0]
        note = connection.execute(
            "SELECT body FROM note WHERE subject_id='artifact'"
        ).fetchone()[0]
        artifact_state = connection.execute(
            "SELECT review_state FROM artifact WHERE artifact_id='artifact'"
        ).fetchone()[0]
    assert (state, review, note, artifact_state) == (
        "in-progress",
        "key_evidence",
        "keep",
        "reviewed",
    )


def test_queue_filters_pagination_and_auxiliary_budgets(tmp_path) -> None:
    root, _, _ = _fixture(tmp_path)
    rebuild_manual_queue(root)
    page = query_manual_queue(
        root,
        min_priority=80,
        offset=1,
        limit=2,
        max_signals=1,
        max_evidence_links=1,
        max_detail_bytes=4,
    )
    assert page.total == 3
    assert page.count == 2
    assert page.signals_returned == 1
    assert page.evidence_links_returned == 1
    assert any(item["signals_truncated"] for item in page.items)
    findings = query_manual_queue(root, kind="finding-review")
    assert findings.total == 1


def test_summary_query_is_independently_paginated(tmp_path) -> None:
    root, _, _ = _fixture(tmp_path)
    page = query_summary(
        root,
        protocol_offset=0,
        protocol_limit=1,
        conversation_offset=0,
        conversation_limit=1,
    )
    assert page.schema_version == "auto-shark.summary/v1"
    assert page.protocol_total == 1
    assert page.protocols[0]["protocol_label"] == "oicq"
    assert page.coverage == {"unavailable": 1}


def test_queue_budget_is_explicit(tmp_path) -> None:
    root, _, _ = _fixture(tmp_path)
    summary = rebuild_manual_queue(root, max_tasks=1, max_signals=1)
    assert summary.status == "budget-limited"
    assert summary.tasks == 1
    assert summary.skipped >= 3
