import json
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from auto_shark import cli
from auto_shark.project import create_project
from auto_shark.storage import Database
from auto_shark.tcp import TcpDirectionSummary, TcpReconstructionSummary
from auto_shark.tcp_text import triage_tcp_text


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _project(tmp_path: Path) -> tuple[Path, Database, int]:
    capture = tmp_path / "capture.pcap"
    capture.write_bytes(b"pcap")
    root = tmp_path / "sample.auto-shark"
    create_project(capture, root, allow_synced=True)
    database = Database(root / "project.sqlite")
    with database.connect() as connection:
        capture_id = int(connection.execute("SELECT id FROM capture").fetchone()[0])
    return root, database, capture_id


def _profile(
    database: Database,
    capture_id: int,
    stream: int,
    payload_bytes: int,
    labels: list[str],
) -> None:
    with database.connect() as connection:
        connection.execute(
            "INSERT INTO conversation_profile "
            "(profile_id,capture_id,protocol,stream_index,endpoint_a,endpoint_b,"
            "initiator_endpoint,responder_endpoint,first_frame,last_frame,first_time,"
            "last_time,frame_count,captured_bytes,wire_bytes,payload_bytes,"
            "protocol_labels_json,updated_at) VALUES(?,?,'tcp',?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                f"profile-{stream}",
                capture_id,
                stream,
                "10.0.0.1:1000",
                "10.0.0.2:2000",
                "10.0.0.1:1000",
                "10.0.0.2:2000",
                1,
                2,
                "1.0",
                "2.0",
                2,
                payload_bytes + 100,
                payload_bytes + 100,
                payload_bytes,
                json.dumps(labels),
                _now(),
            ),
        )


def test_tcp_text_selects_only_bounded_generic_data_streams(tmp_path, monkeypatch) -> None:
    root, database, capture_id = _project(tmp_path)
    _profile(database, capture_id, 0, 38, ["eth", "ip", "tcp", "data"])
    _profile(database, capture_id, 1, 20, ["eth", "ip", "tcp", "http"])
    _profile(database, capture_id, 2, 999, ["eth", "ip", "tcp", "data"])
    _profile(database, capture_id, 3, 50, ["eth", "ip", "tcp", "data"])
    calls = []

    def fake_reconstruct(project, stream, tshark, **limits):
        calls.append((project, stream, tshark, limits))
        direction = TcpDirectionSummary(
            direction=f"stream-{stream}",
            status="complete",
            segments=1,
            sequence_start=1,
            sequence_end=2,
            unique_bytes=10,
            output_bytes=10,
            duplicate_bytes=0,
            conflict_bytes=0,
            gap_bytes=0,
            gaps=0,
            conflicts=0,
            capture_midstream=False,
            evidence_id=f"evidence-{stream}",
            blob_sha256="0" * 64,
        )
        return TcpReconstructionSummary(str(project), stream, 1, 10, 0, False, (direction,))

    monkeypatch.setattr("auto_shark.tcp_text.probe_tshark", lambda _path: object())
    monkeypatch.setattr("auto_shark.tcp_text.reconstruct_tcp_stream", fake_reconstruct)
    monkeypatch.setattr(
        "auto_shark.tcp_text.triage_project",
        lambda *_args, **_kwargs: SimpleNamespace(
            known_matches=1,
            candidates=(SimpleNamespace(value="FLAG:01234567abcdef89"),),
        ),
    )
    monkeypatch.setattr("auto_shark.tcp_text.rebuild_manual_queue", lambda _root: None)

    summary = triage_tcp_text(
        root,
        Path("tshark.exe"),
        max_streams=3,
        max_segments_per_stream=7,
        max_stream_bytes=100,
        max_total_bytes=100,
    )

    assert [item[1] for item in calls] == [0, 3]
    assert summary.profiles_discovered == 4
    assert summary.eligible_streams == 3
    assert summary.excluded_streams == 1
    assert summary.selected_streams == summary.reconstructed_streams == 2
    assert summary.skipped_budget == 1
    assert summary.coverage_status == "budget-limited"
    assert summary.estimated_payload_bytes == 88
    assert summary.output_bytes == 20
    assert summary.candidate_values == ("FLAG:01234567abcdef89",)
    assert calls[0][3]["max_segments"] == 7


def test_tcp_text_cli_forwards_limits(monkeypatch, capsys, tmp_path) -> None:
    received = {}

    def fake_triage(project, tshark, **limits):
        received.update({"project": project, "tshark": tshark, **limits})
        return SimpleNamespace(to_json=lambda: json.dumps({"schema_version": "tcp-text-test"}))

    monkeypatch.setattr(cli, "find_tshark", lambda _path: Path("tshark.exe"))
    monkeypatch.setattr(cli, "triage_tcp_text", fake_triage)
    project = tmp_path / "sample.auto-shark"

    result = cli.main(
        [
            "tcp-text",
            str(project),
            "--max-streams",
            "2",
            "--max-segments-per-stream",
            "3",
            "--max-stream-bytes",
            "5",
            "--max-total-bytes",
            "7",
        ]
    )

    assert result == 0
    assert received == {
        "project": project,
        "tshark": Path("tshark.exe"),
        "max_streams": 2,
        "max_segments_per_stream": 3,
        "max_stream_bytes": 5,
        "max_total_bytes": 7,
    }
    assert json.loads(capsys.readouterr().out)["schema_version"] == "tcp-text-test"


@pytest.mark.parametrize(
    (
        "direction_status",
        "index_truncated",
        "stream_status",
        "coverage_status",
        "partial_streams",
        "truncated_streams",
    ),
    [
        ("partial", False, "partial", "partial", 1, 0),
        ("conflicting", False, "conflicting", "partial", 1, 0),
        ("truncated", False, "truncated", "budget-limited", 0, 1),
        ("complete", True, "truncated", "budget-limited", 0, 1),
    ],
)
def test_tcp_text_propagates_incomplete_reconstruction_status(
    tmp_path,
    monkeypatch,
    direction_status,
    index_truncated,
    stream_status,
    coverage_status,
    partial_streams,
    truncated_streams,
) -> None:
    root, database, capture_id = _project(tmp_path)
    _profile(database, capture_id, 0, 10, ["eth", "ip", "tcp", "data"])
    direction = TcpDirectionSummary(
        direction="a-to-b",
        status=direction_status,
        segments=1,
        sequence_start=1,
        sequence_end=2,
        unique_bytes=10,
        output_bytes=10,
        duplicate_bytes=0,
        conflict_bytes=int(direction_status == "conflicting"),
        gap_bytes=int(direction_status == "partial"),
        gaps=int(direction_status == "partial"),
        conflicts=int(direction_status == "conflicting"),
        capture_midstream=False,
        evidence_id="evidence",
        blob_sha256="0" * 64,
    )
    monkeypatch.setattr("auto_shark.tcp_text.probe_tshark", lambda _path: object())
    monkeypatch.setattr(
        "auto_shark.tcp_text.reconstruct_tcp_stream",
        lambda project, stream, tshark, **limits: TcpReconstructionSummary(
            str(project), stream, 1, 10, 0, index_truncated, (direction,)
        ),
    )
    monkeypatch.setattr(
        "auto_shark.tcp_text.triage_project",
        lambda *_args, **_kwargs: SimpleNamespace(known_matches=0, candidates=()),
    )
    monkeypatch.setattr("auto_shark.tcp_text.rebuild_manual_queue", lambda _root: None)

    summary = triage_tcp_text(root, Path("tshark.exe"))

    assert summary.streams[0].status == stream_status
    assert summary.coverage_status == coverage_status
    assert summary.partial_streams == partial_streams
    assert summary.truncated_streams == truncated_streams
