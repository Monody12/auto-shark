import hashlib
import json
from pathlib import Path

import auto_shark.tcp as tcp_module
from auto_shark.engines.stream import StreamProcessResult
from auto_shark.engines.tshark import TsharkCapabilities
from auto_shark.project import create_project
from auto_shark.protocols.tcp import (
    TCP_FIELDS,
    TCP_REQUIRED_FIELDS,
    parse_tcp_line,
    selected_tcp_fields,
)
from auto_shark.storage import Database
from auto_shark.tcp import reconstruct_tcp_stream


def _line(
    frame: int,
    source: str,
    source_port: int,
    destination: str,
    destination_port: int,
    sequence: int,
    payload: bytes,
    *,
    syn: bool = False,
    retransmission: bool = False,
) -> bytes:
    by_field = {
        "frame.number": str(frame),
        "frame.time_epoch": f"{frame}.0",
        "frame.cap_len": "100",
        "frame.len": "100",
        "ip.src": source,
        "tcp.srcport": str(source_port),
        "ip.dst": destination,
        "tcp.dstport": str(destination_port),
        "tcp.stream": "0",
        "tcp.seq": str(sequence),
        "tcp.seq_raw": str(1000 + sequence),
        "tcp.len": str(len(payload)),
        "tcp.payload": payload.hex(),
        "tcp.flags.syn": "1" if syn else "",
        "tcp.analysis.retransmission": "1" if retransmission else "",
    }
    values = [by_field.get(field, "") for field in TCP_FIELDS]
    return "\t".join(values).encode("ascii")


def _capabilities() -> TsharkCapabilities:
    return TsharkCapabilities(
        executable="fake-tshark",
        version_line="TShark fake",
        fields=tuple(TCP_FIELDS),
        protocols=("tcp",),
        export_objects=(),
        features={"tcp_reassembly": True},
        missing_core_fields=(),
        usable=True,
        errors=(),
    )


def _fake_runner(lines):
    def run(argv, on_line, **kwargs):
        del kwargs
        for line in lines:
            on_line(line)
        return StreamProcessResult(
            argv=tuple(argv),
            returncode=0,
            line_count=len(lines),
            stderr=b"",
            stderr_truncated=False,
            timed_out=False,
            output_limit_exceeded=False,
        )

    return run


def _blob_bytes(project: Path, evidence_id: str) -> bytes:
    database = Database(project / "project.sqlite")
    with database.connect() as connection:
        row = connection.execute(
            "SELECT b.relative_path FROM evidence e JOIN blob b ON b.id=e.blob_id "
            "WHERE e.evidence_id=?",
            (evidence_id,),
        ).fetchone()
    return (project / row[0]).read_bytes()


def test_tcp_parser_rejects_payload_length_mismatch() -> None:
    line = _line(1, "1.1.1.1", 1, "2.2.2.2", 2, 1, b"abc")
    columns = line.decode().split("\t")
    columns[TCP_FIELDS.index("tcp.len")] = "4"
    try:
        parse_tcp_line("\t".join(columns).encode())
    except ValueError as error:
        assert "length mismatch" in str(error)
    else:
        raise AssertionError("length mismatch was accepted")


def test_tcp_parser_allows_unregistered_optional_analysis_fields() -> None:
    available = set(TCP_REQUIRED_FIELDS) | {"ip.src", "ip.dst"}
    selected = selected_tcp_fields(available)
    full_values = dict(
        zip(
            TCP_FIELDS,
            _line(1, "1.1.1.1", 1, "2.2.2.2", 2, 1, b"abc").decode().split("\t"),
        )
    )
    packet = parse_tcp_line(
        "\t".join(full_values[field] for field in selected).encode(),
        selected,
    )
    assert packet.payload == b"abc"
    assert not packet.retransmission


def test_reconstructs_directions_conflicts_gaps_and_retransmissions(tmp_path, monkeypatch) -> None:
    capture = tmp_path / "capture.pcap"
    capture.write_bytes(b"capture")
    project = tmp_path / "sample.auto-shark"
    create_project(capture, project)
    client = ("10.0.0.1", 1234, "10.0.0.2", 80)
    server = ("10.0.0.2", 80, "10.0.0.1", 1234)
    lines = [
        _line(1, *client, 1, b"abc", syn=True),
        _line(2, *client, 4, b"def"),
        _line(3, *client, 1, b"abc", retransmission=True),
        _line(4, *client, 3, b"cXefYZ"),
        _line(5, *client, 10, b"gap"),
        _line(6, *server, 1, b"reply", syn=True),
    ]
    monkeypatch.setattr(tcp_module, "run_streaming_lines", _fake_runner(lines))
    summary = reconstruct_tcp_stream(
        project,
        0,
        Path("fake-tshark"),
        capabilities=_capabilities(),
        max_direction_bytes=1024,
        max_total_output_bytes=2048,
    )
    assert summary.indexed_segments == 6
    by_direction = {item.direction: item for item in summary.directions}
    client_summary = by_direction["10.0.0.1:1234>10.0.0.2:80"]
    server_summary = by_direction["10.0.0.2:80>10.0.0.1:1234"]
    assert client_summary.status == "conflicting"
    assert client_summary.unique_bytes == 11
    assert client_summary.output_bytes == 11
    assert client_summary.duplicate_bytes == 6
    assert client_summary.conflict_bytes == 1
    assert client_summary.gap_bytes == 1
    assert client_summary.gaps == client_summary.conflicts == 1
    assert _blob_bytes(project, client_summary.evidence_id) == b"abcdefYZgap"
    assert server_summary.status == "complete"
    assert not server_summary.capture_midstream
    assert _blob_bytes(project, server_summary.evidence_id) == b"reply"

    database = Database(project / "project.sqlite")
    with database.connect() as connection:
        assert connection.execute("SELECT count(*) FROM tcp_segment").fetchone()[0] == 6
        assert connection.execute("SELECT count(*) FROM tcp_gap").fetchone()[0] == 1
        conflict = connection.execute(
            "SELECT sequence_start,byte_length,first_sha256,conflicting_sha256 "
            "FROM tcp_overlap_conflict"
        ).fetchone()
        assert tuple(conflict[:2]) == (4, 1)
        assert conflict[2] == hashlib.sha256(b"d").hexdigest()
        assert conflict[3] == hashlib.sha256(b"X").hexdigest()
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        frames = connection.execute(
            "SELECT min(frame_start),max(frame_end) FROM evidence WHERE source_kind='tcp-stream'"
        ).fetchone()
        assert tuple(frames) == (1, 6)
    assert list((project / "jobs").iterdir()) == []


def test_index_budget_persists_every_skip_and_isolated_rerun(tmp_path, monkeypatch) -> None:
    capture = tmp_path / "capture.pcap"
    capture.write_bytes(b"capture")
    project = tmp_path / "sample.auto-shark"
    create_project(capture, project)
    endpoints = ("10.0.0.1", 1234, "10.0.0.2", 80)
    lines = [
        _line(1, *endpoints, 1, b"abc", syn=True),
        _line(2, *endpoints, 4, b"def"),
        _line(3, *endpoints, 7, b"ghi"),
    ]
    monkeypatch.setattr(tcp_module, "run_streaming_lines", _fake_runner(lines))
    first = reconstruct_tcp_stream(
        project,
        0,
        Path("fake-tshark"),
        capabilities=_capabilities(),
        max_segments=10,
        max_index_payload_bytes=100,
        max_direction_bytes=100,
        max_total_output_bytes=100,
    )
    assert first.directions[0].output_bytes == 9
    second = reconstruct_tcp_stream(
        project,
        0,
        Path("fake-tshark"),
        capabilities=_capabilities(),
        max_segments=1,
        max_index_payload_bytes=100,
        max_direction_bytes=100,
        max_total_output_bytes=100,
    )
    assert second.indexed_segments == 1
    assert second.skipped_segments == 2
    assert second.index_truncated
    assert second.directions[0].status == "truncated"
    assert second.directions[0].output_bytes == 3
    database = Database(project / "project.sqlite")
    with database.connect() as connection:
        latest_run = connection.execute(
            "SELECT id FROM tool_run ORDER BY id DESC LIMIT 1"
        ).fetchone()[0]
        assert (
            connection.execute(
                "SELECT count(*) FROM tcp_segment_skip WHERE tool_run_id=?", (latest_run,)
            ).fetchone()[0]
            == 2
        )
        assert connection.execute("SELECT count(*) FROM tcp_segment").fetchone()[0] == 3
        assert connection.execute("SELECT count(*) FROM tcp_reconstruction").fetchone()[0] == 1
        assert (
            connection.execute(
                "SELECT count(*) FROM evidence e WHERE e.source_kind='tcp-stream' "
                "AND EXISTS (SELECT 1 FROM tcp_reconstruction tr WHERE tr.evidence_id=e.id)"
            ).fetchone()[0]
            == 1
        )
        assert (
            connection.execute(
                "SELECT count(*) FROM evidence e WHERE e.source_kind='tcp-stream' "
                "AND NOT EXISTS (SELECT 1 FROM tcp_reconstruction tr WHERE tr.evidence_id=e.id)"
            ).fetchone()[0]
            == 1
        )
        assert json.loads(
            connection.execute(
                "SELECT argv_json FROM tool_run WHERE id=?", (latest_run,)
            ).fetchone()[0]
        )[-2:] == ["-e", "tcp.analysis.lost_segment"]


def test_total_output_budget_truncates_later_direction(tmp_path, monkeypatch) -> None:
    capture = tmp_path / "capture.pcap"
    capture.write_bytes(b"capture")
    project = tmp_path / "sample.auto-shark"
    create_project(capture, project)
    client = ("10.0.0.1", 1234, "10.0.0.2", 80)
    server = ("10.0.0.2", 80, "10.0.0.1", 1234)
    lines = [
        _line(1, *client, 10, b"abc"),
        _line(2, *server, 20, b"xyz"),
    ]
    monkeypatch.setattr(tcp_module, "run_streaming_lines", _fake_runner(lines))
    summary = reconstruct_tcp_stream(
        project,
        0,
        Path("fake-tshark"),
        capabilities=_capabilities(),
        max_direction_bytes=100,
        max_total_output_bytes=4,
    )
    assert sum(item.output_bytes for item in summary.directions) == 4
    assert [item.status for item in summary.directions] == ["complete", "truncated"]
    assert all(item.capture_midstream for item in summary.directions)
    assert [item.output_bytes for item in summary.directions] == [3, 1]
