"""M8 release-gate tests: real-TShark smoke, malformed captures, recovery."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from auto_shark.analysis import analyze_http
from auto_shark.engines.tshark import find_tshark
from auto_shark.storage import Database
from auto_shark.workflow import extract_selected_http_bodies

_TSHARK = find_tshark(None)
requires_tshark = pytest.mark.skipif(_TSHARK is None, reason="TShark not available")
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "http-smoke.pcap"


@requires_tshark
def test_real_tshark_analyzes_committed_http_fixture(tmp_path) -> None:
    root = tmp_path / "smoke.auto-shark"
    summary = analyze_http(FIXTURE, root, _TSHARK)
    payload = json.loads(summary.to_json())
    assert payload["http_requests"] == 1
    assert payload["http_responses"] == 1
    assert payload["matched_transactions"] == 1
    assert payload["unmatched_requests"] == 0
    assert payload["orphan_responses"] == 0

    repeat = json.loads(
        analyze_http(FIXTURE, tmp_path / "smoke-repeat.auto-shark", _TSHARK).to_json()
    )
    repeat.pop("project")
    expected = dict(payload)
    expected.pop("project")
    assert repeat == expected

    database = Database(root / "project.sqlite")
    with database.connect() as connection:
        requests = connection.execute(
            "SELECT method,uri,host FROM http_message WHERE method IS NOT NULL"
        ).fetchall()
        responses = connection.execute(
            "SELECT response_code FROM http_message WHERE response_code=200"
        ).fetchall()
    assert [(row["method"], row["uri"], row["host"]) for row in requests] == [
        ("GET", "/probe", "ctf.local")
    ]
    assert len(responses) == 1


@pytest.mark.parametrize(
    "content",
    [
        b"",
        b"\x00\x01",
        b"this is not a capture file at all........",
        b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\xff\xff\x00\x00\x01\x00\x00\x00",
    ],
)
@requires_tshark
def test_malformed_captures_fail_bounded_and_rerun_stable(tmp_path, content) -> None:
    capture = tmp_path / "bad.pcap"
    capture.write_bytes(content)
    outcomes: list[str] = []
    for index in range(2):
        root = tmp_path / f"bad-{index}.auto-shark"
        try:
            summary = analyze_http(capture, root, _TSHARK)
        except (ValueError, TimeoutError):
            outcomes.append("rejected")
        else:
            payload = json.loads(summary.to_json())
            assert payload["http_requests"] == 0
            assert payload["http_responses"] == 0
            outcomes.append("empty")
    assert len(set(outcomes)) == 1, outcomes
    database = Database(tmp_path / "bad-0.auto-shark" / "project.sqlite")
    with database.connect() as connection:
        statuses = [
            str(row[0])
            for row in connection.execute("SELECT status FROM tool_run").fetchall()
        ]
    assert statuses
    assert all(status in ("failed", "completed") for status in statuses)


@requires_tshark
def test_empty_valid_capture_analyzes_to_zero_messages(tmp_path) -> None:
    capture = tmp_path / "empty.pcap"
    capture.write_bytes(
        b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\xff\xff\x00\x00\x01\x00\x00\x00"
    )
    summary = analyze_http(capture, tmp_path / "empty.auto-shark", _TSHARK)
    payload = json.loads(summary.to_json())
    assert payload["http_requests"] == 0
    assert payload["matched_transactions"] == 0


@requires_tshark
def test_interrupted_body_task_state_recovers_on_rerun(tmp_path) -> None:
    root = tmp_path / "recover.auto-shark"
    analyze_http(FIXTURE, root, _TSHARK)

    def run_extraction() -> object:
        return extract_selected_http_bodies(
            root, _TSHARK, uri=None, max_body_bytes=1024, max_total_bytes=4096
        )

    first = run_extraction()
    assert first.completed == 2

    connection = sqlite3.connect(root / "project.sqlite")
    connection.execute(
        "UPDATE body_task SET status='running', error='simulated interruption' "
        "WHERE status='completed'"
    )
    connection.commit()
    stale = connection.execute(
        "SELECT count(*) FROM body_task WHERE status='running'"
    ).fetchone()[0]
    connection.close()
    assert stale >= 1

    second = run_extraction()
    assert second.completed == 2
    connection = sqlite3.connect(root / "project.sqlite")
    remaining = connection.execute(
        "SELECT count(*) FROM body_task WHERE status='running'"
    ).fetchone()[0]
    connection.close()
    assert remaining == 0
