import json
from datetime import datetime, timezone

import pytest

from auto_shark.exporting import ExportLimits, export_bundle
from auto_shark.investigation import add_note, set_review_mark
from auto_shark.project import create_project
from auto_shark.reporting import ReportLimits, collect_report
from auto_shark.storage import SCHEMA_VERSION, Database


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _report_project(tmp_path):
    capture = tmp_path / "source.pcap"
    capture.write_bytes(b"pcap")
    root = tmp_path / "report.auto-shark"
    create_project(capture, root, allow_synced=True)
    database = Database(root / "project.sqlite")
    with database.connect() as connection:
        capture_id = int(connection.execute("SELECT id FROM capture").fetchone()[0])
        connection.execute(
            "INSERT INTO blob"
            "(sha256,byte_length,relative_path,media_type,complete,created_at) "
            "VALUES('blob-hash',12,'blobs/private.bin','application/octet-stream',1,?)",
            (_now(),),
        )
        blob_id = int(connection.execute("SELECT id FROM blob").fetchone()[0])
        for ordinal in range(2):
            connection.execute(
                "INSERT INTO evidence"
                "(evidence_id,capture_id,source_kind,frame_start,frame_end,byte_offset,"
                "byte_length,text_value,blob_id,locator_json) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    f"evidence-{ordinal}",
                    capture_id,
                    "test",
                    ordinal + 1,
                    ordinal + 1,
                    ordinal,
                    1,
                    "SECRET_BLOB_TEXT",
                    blob_id,
                    json.dumps({"local": str(root)}),
                ),
            )
        evidence_id = int(
            connection.execute(
                "SELECT id FROM evidence WHERE evidence_id='evidence-0'"
            ).fetchone()[0]
        )
        connection.execute(
            "INSERT INTO candidate"
            "(candidate_id,kind,raw_value,normalized_value,confidence,rank_score,created_at) "
            "VALUES('candidate-1','known-flag','flag{safe}','flag{safe}',1,100,?)",
            (_now(),),
        )
        candidate_id = int(connection.execute("SELECT id FROM candidate").fetchone()[0])
        connection.execute(
            "INSERT INTO candidate_evidence(candidate_id,evidence_id,role) VALUES(?,?,'match')",
            (candidate_id, evidence_id),
        )
        connection.execute(
            "INSERT INTO candidate_signal"
            "(signal_id,candidate_id,evidence_id,detector,detector_version,signal_name,"
            "contribution,detail_json) VALUES('signal-1',?,?, 'test','1','match',100,?)",
            (candidate_id, evidence_id, json.dumps({"path": str(root)})),
        )
        connection.execute(
            "INSERT INTO artifact"
            "(artifact_id,blob_id,source_evidence_id,suggested_name,detected_media_type,"
            "review_state,created_at) VALUES('artifact-1',?,?,'sample.bin',"
            "'application/octet-stream','unreviewed',?)",
            (blob_id, evidence_id, _now()),
        )
        connection.execute(
            "INSERT INTO tool_run"
            "(run_id,tool_name,tool_version,argv_json,started_at,ended_at,status,exit_code,"
            "stderr_text) VALUES('tool-1','test','1',?, ?,?,'completed',0,?)",
            (json.dumps([str(capture)]), _now(), _now(), str(root)),
        )
    set_review_mark(root, "candidate", "candidate-1", "key_evidence")
    add_note(root, "candidate", "candidate-1", "reviewed")
    return root, capture


def test_report_is_deterministic_bounded_and_excludes_local_or_blob_data(tmp_path) -> None:
    root, capture = _report_project(tmp_path)
    limits = ReportLimits(evidence=1, detail_bytes=128, note_bytes=128)

    first = collect_report(root, limits=limits).to_json()
    second = collect_report(root, limits=limits).to_json()
    payload = json.loads(first)

    assert first == second
    assert first.endswith("\n") and not first.endswith("\n\n")
    assert payload["schema_version"] == "auto-shark.report/v1"
    assert payload["capture"]["database_schema"] == SCHEMA_VERSION
    assert payload["overview"]["candidates"] == 1
    assert payload["artifacts"]["total"] == 1
    assert payload["review_marks"]["total"] == 1
    assert payload["notes"]["total"] == 1
    assert payload["evidence"]["count"] == 1
    assert payload["evidence"]["total"] == 2
    assert payload["evidence"]["truncated"] is True
    assert "argv_json" not in payload["tool_runs"]["items"][0]
    assert "stderr_text" not in payload["tool_runs"]["items"][0]
    assert str(root) not in first
    assert str(capture) not in first
    assert "blobs/private.bin" not in first
    assert "SECRET_BLOB_TEXT" not in first


def test_report_rejects_nonpositive_and_unbounded_limits(tmp_path) -> None:
    root, _ = _report_project(tmp_path)
    with pytest.raises(ValueError, match="positive"):
        collect_report(root, limits=ReportLimits(events=0))
    with pytest.raises(ValueError, match="cannot exceed"):
        collect_report(root, limits=ReportLimits(candidates=1001))
    with pytest.raises(ValueError, match="cannot exceed"):
        collect_report(root, limits=ReportLimits(evidence=100_001))


def test_export_bundle_is_self_contained_exact_and_repeatable(tmp_path) -> None:
    root, _ = _report_project(tmp_path)
    (root / "blobs" / "private.bin").write_bytes(b"abcdefghijkl")
    first_dir = tmp_path / "export-one"
    second_dir = tmp_path / "export-two"
    first = export_bundle(root, first_dir)
    second = export_bundle(root, second_dir)

    assert first.report_sha256 == second.report_sha256
    assert first.html_sha256 == second.html_sha256
    assert first.evidence_items == second.evidence_items == 2
    assert first.evidence_bytes == second.evidence_bytes == 2
    first_files = sorted(
        path.relative_to(first_dir).as_posix() for path in first_dir.rglob("*") if path.is_file()
    )
    second_files = sorted(
        path.relative_to(second_dir).as_posix() for path in second_dir.rglob("*") if path.is_file()
    )
    assert first_files == second_files == [
        "evidence/evidence-0.bin",
        "evidence/evidence-1.bin",
        "manifest.json",
        "report.html",
        "report.json",
    ]
    for relative in first_files:
        assert (first_dir / relative).read_bytes() == (second_dir / relative).read_bytes()
    assert (first_dir / "evidence/evidence-0.bin").read_bytes() == b"a"
    assert (first_dir / "evidence/evidence-1.bin").read_bytes() == b"b"
    manifest = json.loads((first_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["schema_version"] == "auto-shark.export/v1"
    assert manifest["evidence_skips"] == []
    html = (first_dir / "report.html").read_text(encoding="utf-8")
    assert "<script" not in html.lower()
    assert "https://" not in html
    assert "<table" in html and "<h2>Capture</h2>" in html
    assert "flag{safe}" in html  # candidate value rendered and escaped-safe
    assert "<details>" in html and "report JSON" in html
    assert "SECRET_BLOB_TEXT" not in html


def test_export_bundle_records_missing_and_budget_skips(tmp_path) -> None:
    root, _ = _report_project(tmp_path)
    (root / "blobs" / "private.bin").write_bytes(b"abcdefghijkl")
    budget = export_bundle(
        root,
        tmp_path / "budget-export",
        export_limits=ExportLimits(max_evidence_total_bytes=1),
    )
    assert budget.evidence_items == 1
    assert budget.evidence_skips == 1
    budget_manifest = json.loads(
        (tmp_path / "budget-export" / "manifest.json").read_text(encoding="utf-8")
    )
    assert budget_manifest["evidence_skips"][0]["reason"] == "total-byte-limit"

    (root / "blobs" / "private.bin").unlink()
    missing = export_bundle(root, tmp_path / "missing-export")
    assert missing.evidence_items == 0
    assert missing.evidence_skips == 2
    with pytest.raises(ValueError, match="new or empty"):
        export_bundle(root, tmp_path / "budget-export")


def test_report_recognizes_voip_and_recommends_rtp_workflow(tmp_path) -> None:
    root, _ = _report_project(tmp_path)
    database = Database(root / "project.sqlite")
    with database.connect() as connection:
        capture_id = int(connection.execute("SELECT id FROM capture").fetchone()[0])
        tool_id = int(connection.execute("SELECT id FROM tool_run").fetchone()[0])
        connection.execute(
            "INSERT INTO capture_inventory_run "
            "(inventory_run_id,capture_id,tool_run_id,policy_json,status,processed_frames,"
            "skipped_frames,skipped_conversations,skipped_protocol_labels,started_at,ended_at) "
            "VALUES('voip-inventory',?,?,'{}','completed',500,0,0,0,?,?)",
            (capture_id, tool_id, _now(), _now()),
        )
        inventory_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
        for label, count in (("rtp", 480), ("rtpevent", 20), ("sip", 8)):
            connection.execute(
                "INSERT INTO protocol_observation "
                "(observation_id,capture_id,protocol_label,frame_count,first_frame,last_frame,"
                "inventory_run_id,updated_at) VALUES(?,?,?,?,1,500,?,?)",
                (f"protocol-{label}", capture_id, label, count, inventory_id, _now()),
            )

    assessment = collect_report(root).payload["assessment"]

    assert assessment["behaviors"][0]["kind"] == "voip-traffic"
    assert assessment["behaviors"][0]["count"] == 480
    assert "voip-extract" in assessment["behaviors"][0]["hint"]
    assert any("telephone-event" in item for item in assessment["suggested_focus"])


def test_report_maps_icmp_ttl_oracle_finding(tmp_path) -> None:
    root, _ = _report_project(tmp_path)
    database = Database(root / "project.sqlite")
    with database.connect() as connection:
        connection.execute(
            "INSERT INTO finding(finding_id,detector,detector_version,title,description,"
            "severity,confidence,created_at) VALUES('icmp-finding',"
            "'icmp-ttl-oracle','1','TTL oracle','selective replies','high',0.92,?)",
            (_now(),),
        )
        finding_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
        evidence_id = int(
            connection.execute(
                "SELECT id FROM evidence WHERE evidence_id='evidence-0'"
            ).fetchone()[0]
        )
        connection.execute(
            "INSERT INTO finding_evidence(finding_id,evidence_id,role) VALUES(?,?,?)",
            (finding_id, evidence_id, "icmp-ttl-probe-series"),
        )

    behaviors = collect_report(root).payload["assessment"]["behaviors"]
    item = next(value for value in behaviors if value["kind"] == "icmp-ttl-oracle")

    assert item["count"] == 1
    assert "reply" in item["hint"] and "uncaptured" in item["hint"]


def test_report_maps_ognl_findings_to_web_command_execution(tmp_path) -> None:
    root, _ = _report_project(tmp_path)
    database = Database(root / "project.sqlite")
    with database.connect() as connection:
        connection.execute(
            "INSERT INTO finding(finding_id,detector,detector_version,title,description,"
            "severity,confidence,created_at) VALUES('ognl-finding',"
            "'struts-ognl-command-injection','1','OGNL','command','critical',0.99,?)",
            (_now(),),
        )
        finding_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
        evidence_id = int(
            connection.execute(
                "SELECT id FROM evidence WHERE evidence_id='evidence-0'"
            ).fetchone()[0]
        )
        connection.execute(
            "INSERT INTO finding_evidence(finding_id,evidence_id,role) VALUES(?,?,?)",
            (finding_id, evidence_id, "command-expression"),
        )

    behaviors = collect_report(root).payload["assessment"]["behaviors"]
    item = next(value for value in behaviors if value["kind"] == "web-command-execution")

    assert item["count"] == 1
    assert "form field name" in item["hint"] and "correlated HTTP response" in item["hint"]
