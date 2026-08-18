import json

from auto_shark.engines.stream import StreamProcessResult
from auto_shark.engines.tshark import TsharkCapabilities
from auto_shark.project import create_project
from auto_shark.storage import Database
from auto_shark.tcp_urgent import (
    URGENT_FIELDS,
    parse_urgent_line,
    triage_tcp_urgent,
)


def _line(frame: int, pointer: int, *, stream: int = 3) -> bytes:
    values = {
        "frame.number": str(frame),
        "tcp.stream": str(stream),
        "ip.src": "192.0.2.10",
        "ipv6.src": "",
        "ip.dst": "192.0.2.20",
        "ipv6.dst": "",
        "tcp.flags.urg": "1",
        "tcp.urgent_pointer": str(pointer),
    }
    return "\t".join(f'"{values[field]}"' for field in URGENT_FIELDS).encode()


def test_parse_urgent_line() -> None:
    assert parse_urgent_line(_line(7, 67)) == (7, 3, "192.0.2.10", "192.0.2.20", 67)
    assert parse_urgent_line(_line(8, 0)) is None


def test_triage_tcp_urgent_persists_text_and_flag(tmp_path, monkeypatch) -> None:
    capture = tmp_path / "urgent.pcap"
    capture.write_bytes(b"pcap")
    root = tmp_path / "urgent.auto-shark"
    create_project(capture, root, allow_synced=True)
    capabilities = TsharkCapabilities(
        executable="fake-tshark",
        version_line="TShark test",
        fields=URGENT_FIELDS,
        protocols=("tcp",),
        export_objects=(),
        features={"tcp_urgent": True},
        missing_core_fields=(),
        usable=True,
        errors=(),
    )
    monkeypatch.setattr("auto_shark.tcp_urgent.probe_tshark", lambda _path: capabilities)
    values = b"CTF{urgent-side-channel}"
    lines = [_line(index, value) for index, value in enumerate(values, 1)]

    def fake_run(argv, on_line, **_kwargs):
        for line in lines:
            on_line(line)
        return StreamProcessResult(tuple(argv), 0, len(lines), b"", False, False, False)

    monkeypatch.setattr("auto_shark.tcp_urgent.run_streaming_lines", fake_run)
    executable = tmp_path / "tshark.exe"
    executable.write_bytes(b"")

    summary = triage_tcp_urgent(root, executable)
    assert summary.status == "completed"
    assert summary.groups[0].text == values.decode()
    assert summary.groups[0].flags == (values.decode(),)
    with Database(root / "project.sqlite").connect() as connection:
        assert connection.execute(
            "SELECT count(*) FROM evidence WHERE source_kind='tcp-urgent-pointer'"
        ).fetchone()[0] == 1
        candidate = connection.execute(
            "SELECT normalized_value FROM candidate WHERE kind='tcp-urgent-flag'"
        ).fetchone()
        assert candidate[0] == values.decode()
        locator = json.loads(
            connection.execute(
                "SELECT locator_json FROM evidence WHERE source_kind='tcp-urgent-pointer'"
            ).fetchone()[0]
        )
        tool_run = connection.execute(
            "SELECT status,exit_code FROM tool_run ORDER BY id DESC LIMIT 1"
        ).fetchone()
    assert locator["detector"] == "auto-shark.tcp-urgent-pointer/v1"
    assert tuple(tool_run) == ("completed", 0)


def test_tcp_urgent_reports_frame_budget_exhaustion(tmp_path, monkeypatch) -> None:
    capture = tmp_path / "urgent-budget.pcap"
    capture.write_bytes(b"pcap")
    root = tmp_path / "urgent-budget.auto-shark"
    create_project(capture, root, allow_synced=True)
    capabilities = TsharkCapabilities(
        executable="fake-tshark",
        version_line="TShark test",
        fields=URGENT_FIELDS,
        protocols=("tcp",),
        export_objects=(),
        features={"tcp_urgent": True},
        missing_core_fields=(),
        usable=True,
        errors=(),
    )
    monkeypatch.setattr("auto_shark.tcp_urgent.probe_tshark", lambda _path: capabilities)

    def fake_run(argv, on_line, **_kwargs):
        for frame in range(1, 5):
            on_line(_line(frame, 64 + frame))
        return StreamProcessResult(tuple(argv), 0, 4, b"", False, False, False)

    monkeypatch.setattr("auto_shark.tcp_urgent.run_streaming_lines", fake_run)
    summary = triage_tcp_urgent(root, tmp_path / "tshark.exe", max_frames=2)

    assert summary.status == "budget-limited"
    assert summary.frames_seen == 4
    assert summary.skipped_frame_limit == 2
    with Database(root / "project.sqlite").connect() as connection:
        assert connection.execute(
            "SELECT status FROM tool_run ORDER BY id DESC LIMIT 1"
        ).fetchone()[0] == "budget-limited"
