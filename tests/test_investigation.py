from datetime import datetime, timezone

import pytest

from auto_shark.investigation import add_note, query_notes, set_review_mark, update_note
from auto_shark.project import create_project
from auto_shark.storage import Database


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _project_with_candidate(tmp_path):
    capture = tmp_path / "sample.pcap"
    capture.write_bytes(b"pcap")
    root = tmp_path / "sample.auto-shark"
    create_project(capture, root, allow_synced=True)
    database = Database(root / "project.sqlite")
    with database.connect() as connection:
        capture_id = int(connection.execute("SELECT id FROM capture").fetchone()[0])
        connection.execute(
            "INSERT INTO evidence"
            "(evidence_id,capture_id,source_kind,byte_offset,byte_length,text_value,locator_json) "
            "VALUES('evidence-1',?,'test',0,5,'value','{}')",
            (capture_id,),
        )
        evidence_id = int(connection.execute("SELECT id FROM evidence").fetchone()[0])
        connection.execute(
            "INSERT INTO candidate"
            "(candidate_id,kind,raw_value,normalized_value,confidence,rank_score,created_at) "
            "VALUES('candidate-1','test','value','value',0.8,80,?)",
            (_now(),),
        )
        candidate_id = int(connection.execute("SELECT id FROM candidate").fetchone()[0])
        connection.execute(
            "INSERT INTO candidate_evidence(candidate_id,evidence_id,role) VALUES(?,?,'match')",
            (candidate_id, evidence_id),
        )
    return root


def test_review_marks_validate_subject_and_upsert(tmp_path) -> None:
    root = _project_with_candidate(tmp_path)
    first = set_review_mark(root, "candidate", "candidate-1", "needs_review")
    second = set_review_mark(root, "candidate", "candidate-1", "key_evidence")

    assert first["schema_version"] == "auto-shark.review-mark/v1"
    assert second["state"] == "key_evidence"
    with Database(root / "project.sqlite").connect() as connection:
        rows = connection.execute(
            "SELECT subject_kind,subject_id,state FROM review_mark"
        ).fetchall()
    assert [tuple(row) for row in rows] == [("candidate", "candidate-1", "key_evidence")]
    with pytest.raises(ValueError, match="not found"):
        set_review_mark(root, "candidate", "other-project-id", "excluded")
    with pytest.raises(ValueError, match="invalid review"):
        set_review_mark(root, "transaction", "candidate-1", "excluded")


def test_notes_backfill_create_update_filter_and_utf8_limits(tmp_path) -> None:
    root = _project_with_candidate(tmp_path)
    database = Database(root / "project.sqlite")
    with database.connect() as connection:
        connection.execute(
            "INSERT INTO note(subject_kind,subject_id,body,created_at,updated_at) "
            "VALUES('candidate','candidate-1','legacy',?,?)",
            (_now(), _now()),
        )

    legacy = query_notes(root)
    repeated = query_notes(root)
    assert legacy.to_json() == repeated.to_json()
    assert legacy.total == 1
    assert len(legacy.items[0]["note_id"]) == 64

    created = add_note(root, "candidate", "candidate-1", "manual note")
    updated = update_note(root, str(created["note_id"]), "updated note")
    assert updated["body"] == "updated note"
    page = query_notes(
        root,
        subject_kind="candidate",
        subject_id="candidate-1",
        limit=1,
        max_body_bytes=3,
    )
    assert page.total == 2 and page.count == 1
    assert page.items[0]["body_truncated"]

    with pytest.raises(ValueError, match="UTF-8 bytes"):
        add_note(root, "candidate", "candidate-1", "测试", max_note_bytes=5)
    with pytest.raises(ValueError, match="cannot be empty"):
        add_note(root, "candidate", "candidate-1", "  ")
    with pytest.raises(ValueError, match="not found"):
        update_note(root, "missing", "body")
