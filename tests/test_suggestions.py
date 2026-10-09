"""Wizard composition rules over indexed read models."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from auto_shark.project import create_project, write_flag_format
from auto_shark.storage import Database
from auto_shark.suggestions import (
    _assessment_suggestions,
    _flag_candidates,
    _http_suggestions,
    _protocol_suggestions,
    _stream_suggestions,
    build_wizard,
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _project_with_candidate(tmp_path: Path) -> Path:
    capture = tmp_path / "cap.pcap"
    capture.write_bytes(b"pcap")
    root = tmp_path / "case.auto-shark"
    create_project(capture, root, allow_synced=True)
    database = Database(root / "project.sqlite")
    with database.connect() as connection:
        capture_id = int(connection.execute("SELECT id FROM capture").fetchone()[0])
        connection.execute(
            "INSERT INTO evidence"
            "(evidence_id,capture_id,source_kind,frame_start,frame_end,byte_offset,"
            "byte_length,text_value,blob_id,locator_json) "
            "VALUES('ev-1',?,'test',1,1,0,4,'flag{gui}',NULL,?)",
            (capture_id, json.dumps({"local": str(root)})),
        )
        evidence_id = int(
            connection.execute("SELECT id FROM evidence WHERE evidence_id='ev-1'").fetchone()[0]
        )
        connection.execute(
            "INSERT INTO candidate"
            "(candidate_id,kind,raw_value,normalized_value,confidence,rank_score,created_at) "
            "VALUES('c-1','known-flag','flag{abc}','flag{abc}',1,100,?),"
            "('c-2','sensitive-field','SUCTF{zzz}','SUCTF{zzz}',0.5,60,?)",
            (_now(), _now()),
        )
        for candidate_row in connection.execute("SELECT id FROM candidate").fetchall():
            connection.execute(
                "INSERT INTO candidate_evidence(candidate_id,evidence_id,role) "
                "VALUES(?,?,'match')",
                (candidate_row["id"], evidence_id),
            )
    return root


def test_http_upload_and_directory_bruteforce_rules(tmp_path, monkeypatch) -> None:
    def fake_transactions(_root, **_kwargs):
        items = []
        for index in range(30):
            items.append(
                {
                    "request": {"frame": index + 1, "method": "GET", "uri": f"/{index}.php"},
                    "response": {"code": 404},
                }
            )
        items.append(
            {
                "request": {"frame": 99, "method": "POST", "uri": "/upload.php"},
                "response": {"code": 200},
            }
        )
        return {"items": items}

    monkeypatch.setattr("auto_shark.suggestions.query_transactions", fake_transactions)
    suggestions = _http_suggestions(tmp_path, {})
    kinds = {item.kind: item for item in suggestions}
    assert kinds["http-upload"].action == "files"
    assert "upload.php" in kinds["http-upload"].evidence
    assert kinds["directory-bruteforce"].action == "http"


def test_protocol_rules_fire_for_usb_telnet_dns(tmp_path) -> None:
    summary = {
        "protocols": [
            {"protocol_label": "dns", "frame_count": 500},
            {"protocol_label": "usb", "frame_count": 200},
            {"protocol_label": "telnet", "frame_count": 30},
            {"protocol_label": "tcp", "frame_count": 50},
        ]
    }
    kinds = {item.kind: item for item in _protocol_suggestions(summary)}
    assert kinds["usb-hid"].action == "findings"
    assert kinds["telnet-credentials"].action == "telnet"
    assert kinds["dns-tunnel"].action == "findings"


def test_assessment_kinds_use_player_chinese_titles() -> None:
    report = {
        "assessment": {
            "behaviors": [
                {
                    "kind": "http-status-body-contradiction",
                    "count": 1,
                    "hint": "Review the finding evidence links.",
                },
                {
                    "kind": "webshell-activity",
                    "count": 1,
                    "hint": "Follow the operation timeline.",
                },
                {
                    "kind": "usb-hid-triage",
                    "count": 1,
                    "hint": "Review key-down/release edges.",
                },
            ]
        }
    }
    kinds = {item.kind: item for item in _assessment_suggestions(report)}
    assert "webshell-activity" not in kinds
    assert "usb-hid-triage" not in kinds
    contradiction = kinds["http-status-body-contradiction"]
    assert contradiction.title == "HTTP 状态与正文矛盾"
    assert contradiction.action == "http"
    assert "HTTP" in contradiction.detail


def test_assessment_maps_repair_and_encrypted_archive(tmp_path) -> None:
    report = {
        "assessment": {
            "behaviors": [
                {
                    "kind": "pcap-header-repair",
                    "count": 1,
                    "hint": "Review the finding evidence links.",
                },
                {
                    "kind": "password-protected-archive",
                    "count": 1,
                    "hint": "Review the finding evidence links.",
                },
                {
                    "kind": "nested-container",
                    "count": 1,
                    "hint": "Review the finding evidence links.",
                },
            ]
        }
    }
    kinds = {item.kind: item for item in _assessment_suggestions(report)}
    assert kinds["pcap-header-repair"].action == "findings"
    assert "修复" in kinds["pcap-header-repair"].title
    assert kinds["password-protected-archive"].action == "files"
    assert kinds["nested-container"].action == "files"


def test_tcp_payload_suggestion_when_only_generic_streams(tmp_path, monkeypatch) -> None:
    def fake_streams(_root, **_kwargs):
        return {
            "items": [
                {
                    "stream_index": 0,
                    "bytes": {"output": 38},
                    "direction": "172.31.98.199:46046>192.155.81.86:7890",
                }
            ]
        }

    monkeypatch.setattr("auto_shark.suggestions.query_streams", fake_streams)
    summary = {"protocols": [{"protocol_label": "tcp", "frame_count": 82}]}
    items = _stream_suggestions(tmp_path, summary)
    assert items[0].kind == "tcp-payload"
    assert items[0].action == "streams"
    http_summary = {
        "protocols": [
            {"protocol_label": "tcp", "frame_count": 82},
            {"protocol_label": "http", "frame_count": 8},
        ]
    }
    assert _stream_suggestions(tmp_path, http_summary) == []


def test_flag_candidates_rank_user_format_first(tmp_path, monkeypatch) -> None:
    def fake_findings(_root, **_kwargs):
        return {
            "candidates": [
                {"normalized_value": "flag{abc}", "kind": "known-flag", "rank_score": 100},
                {"normalized_value": "SUCTF{zzz}", "kind": "sensitive-field", "rank_score": 60},
            ]
        }

    monkeypatch.setattr("auto_shark.suggestions.query_findings", fake_findings)
    ranked = _flag_candidates(tmp_path, r"SUCTF\{[^}]+\}")
    assert ranked[0]["value"] == "SUCTF{zzz}"
    assert ranked[0]["user_format_match"] is True
    assert ranked[1]["user_format_match"] is False


def test_build_wizard_on_minimal_project_returns_fallback(tmp_path) -> None:
    root = _project_with_candidate(tmp_path)
    wizard = build_wizard(root)

    assert wizard["schema_version"] == "auto-shark.wizard/v1"
    assert wizard["flag_format"] is None
    assert wizard["fallback_steps"][0]["title"].startswith("1.")
    values = [item["value"] for item in wizard["flag_candidates"]]
    assert values == ["flag{abc}", "SUCTF{zzz}"]

    write_flag_format(root, r"SUCTF\{[^}]+\}")
    wizard = build_wizard(root)
    assert wizard["flag_format"] == r"SUCTF\{[^}]+\}"
    assert wizard["flag_candidates"][0]["user_format_match"] is True
