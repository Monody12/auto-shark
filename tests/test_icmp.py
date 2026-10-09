from __future__ import annotations

import json

from auto_shark.engines.stream import StreamProcessResult
from auto_shark.engines.tshark import TsharkCapabilities
from auto_shark.icmp import ICMP_FIELDS, parse_icmp_line, triage_icmp
from auto_shark.project import create_project
from auto_shark.storage import Database


def _line(
    frame: int,
    ttl: int,
    *,
    message_type: int = 8,
    response_to: int | None = None,
) -> bytes:
    request = message_type == 8
    values = {
        "frame.number": str(frame),
        "frame.time_epoch": f"1700000000.{frame:06d}",
        "ip.src": "192.0.2.10" if request else "192.0.2.20",
        "ip.dst": "192.0.2.20" if request else "192.0.2.10",
        "ip.ttl": str(ttl),
        "icmp.type": str(message_type),
        "icmp.code": "0",
        "icmp.ident": str(40000 + frame),
        "icmp.seq": "1",
        "icmp.resp_to": str(response_to) if response_to is not None else "",
    }
    return "\t".join(f'"{values[field]}"' for field in ICMP_FIELDS).encode()


def _capabilities() -> TsharkCapabilities:
    return TsharkCapabilities(
        executable="fake-tshark",
        version_line="TShark test",
        fields=ICMP_FIELDS,
        protocols=("icmp",),
        export_objects=(),
        features={},
        missing_core_fields=(),
        usable=True,
        errors=(),
    )


def test_parse_icmp_request_and_reply() -> None:
    request = parse_icmp_line(_line(7, 73))
    reply = parse_icmp_line(_line(8, 128, message_type=0, response_to=7))

    assert request.frame == 7 and request.ttl == 73 and request.response_to is None
    assert reply.message_type == 0 and reply.response_to == 7


def test_triage_icmp_persists_printable_ttl_oracle(tmp_path, monkeypatch) -> None:
    capture = tmp_path / "oracle.pcap"
    capture.write_bytes(b"pcap")
    root = tmp_path / "oracle.auto-shark"
    create_project(capture, root, allow_synced=True)
    monkeypatch.setattr("auto_shark.icmp.probe_tshark", lambda _path: _capabilities())

    attempts = "RSTUTRTSTTKTTL"
    replied_indexes = {2, 4, 6, 8, 9, 11, 12, 13}
    lines = []
    frame = 1
    for index, char in enumerate(attempts):
        request_frame = frame
        lines.append(_line(request_frame, ord(char)))
        frame += 1
        if index in replied_indexes:
            lines.append(_line(frame, 128, message_type=0, response_to=request_frame))
            frame += 1

    def fake_run(argv, on_line, **_kwargs):
        for line in lines:
            on_line(line)
        return StreamProcessResult(tuple(argv), 0, len(lines), b"", False, False, False)

    monkeypatch.setattr("auto_shark.icmp.run_streaming_lines", fake_run)
    executable = tmp_path / "tshark.exe"
    executable.write_bytes(b"")

    summary = triage_icmp(root, executable)

    assert summary.status == "completed"
    assert summary.requests_seen == 14 and summary.replies_seen == 8
    route = summary.routes[0]
    assert route.classification == "printable-ttl-selective-replies"
    assert route.attempt_text == attempts
    assert route.accepted_text == "TTTTTTTL"
    assert route.score == 100
    with Database(root / "project.sqlite").connect() as connection:
        evidence = connection.execute(
            "SELECT locator_json FROM evidence WHERE source_kind='icmp-echo-probe-series'"
        ).fetchone()
        finding = connection.execute(
            "SELECT recommended_action FROM finding WHERE detector='icmp-ttl-oracle'"
        ).fetchone()
        tool_run = connection.execute(
            "SELECT status,exit_code FROM tool_run ORDER BY id DESC LIMIT 1"
        ).fetchone()
    locator = json.loads(evidence[0])
    assert locator["response_bitmap"] == route.response_bitmap
    assert locator["attempts"][2]["reply_frame"] is not None
    assert "partial capture" in finding[0]
    assert tuple(tool_run) == ("completed", 0)


def test_triage_icmp_does_not_promote_constant_ttl_ping(tmp_path, monkeypatch) -> None:
    capture = tmp_path / "normal.pcap"
    capture.write_bytes(b"pcap")
    root = tmp_path / "normal.auto-shark"
    create_project(capture, root, allow_synced=True)
    monkeypatch.setattr("auto_shark.icmp.probe_tshark", lambda _path: _capabilities())
    lines = []
    for index in range(1, 11):
        request_frame = index * 2 - 1
        lines.extend(
            (
                _line(request_frame, 64),
                _line(index * 2, 128, message_type=0, response_to=request_frame),
            )
        )

    def fake_run(argv, on_line, **_kwargs):
        for line in lines:
            on_line(line)
        return StreamProcessResult(tuple(argv), 0, len(lines), b"", False, False, False)

    monkeypatch.setattr("auto_shark.icmp.run_streaming_lines", fake_run)
    executable = tmp_path / "tshark.exe"
    executable.write_bytes(b"")

    summary = triage_icmp(root, executable)

    assert summary.routes[0].classification == "ordinary-or-inconclusive"
    assert summary.routes[0].evidence_id is None
    with Database(root / "project.sqlite").connect() as connection:
        assert connection.execute(
            "SELECT count(*) FROM finding WHERE detector='icmp-ttl-oracle'"
        ).fetchone()[0] == 0


def test_triage_icmp_data_stores_concatenated_payload_evidence(tmp_path, monkeypatch) -> None:
    from auto_shark.icmp import triage_icmp_data

    capture = tmp_path / "data.pcap"
    capture.write_bytes(b"pcap")
    root = tmp_path / "data.auto-shark"
    create_project(capture, root, allow_synced=True)
    capabilities = _capabilities()
    monkeypatch.setattr(
        "auto_shark.icmp.probe_tshark",
        lambda _path: capabilities.__class__(
            executable="fake-tshark",
            version_line="TShark test",
            fields=ICMP_FIELDS + ("data.data",),
            protocols=("icmp",),
            export_objects=(),
            features={},
            missing_core_fields=(),
            usable=True,
            errors=(),
        ),
    )

    def fake_run(_argv, on_line, **_kwargs):
        # One printable fragment per ping, hex-encoded by tshark.
        on_line(b'1\t666c61677b69636d70')  # "flag{icmp"
        on_line(b'2\t2d646174617d')  # "-data}"
        return StreamProcessResult((), 0, 2, b"", False, False, False)

    monkeypatch.setattr("auto_shark.icmp.run_streaming_lines", fake_run)
    executable = tmp_path / "tshark.exe"
    executable.write_bytes(b"")

    summary = triage_icmp_data(root, executable)

    assert summary.status == "stored"
    assert summary.frames == 2
    assert summary.payload_bytes == len(b"flag{icmp-data}")
    with Database(root / "project.sqlite").connect() as connection:
        row = connection.execute(
            "SELECT e.text_value, b.byte_length FROM evidence e "
            "JOIN blob b ON b.id=e.blob_id WHERE e.source_kind='icmp-data-stream'"
        ).fetchone()
    assert row is not None
    assert row[0].startswith("flag{icmp-data}")
    assert row[1] == len(b"flag{icmp-data}")


def test_triage_icmp_data_reports_no_payloads(tmp_path, monkeypatch) -> None:
    from auto_shark.icmp import triage_icmp_data

    capture = tmp_path / "plain.pcap"
    capture.write_bytes(b"pcap")
    root = tmp_path / "plain.auto-shark"
    create_project(capture, root, allow_synced=True)
    monkeypatch.setattr(
        "auto_shark.icmp.probe_tshark",
        lambda _path: _capabilities().__class__(
            executable="fake-tshark",
            version_line="TShark test",
            fields=ICMP_FIELDS + ("data.data",),
            protocols=("icmp",),
            export_objects=(),
            features={},
            missing_core_fields=(),
            usable=True,
            errors=(),
        ),
    )

    def fake_run(_argv, on_line, **_kwargs):
        return StreamProcessResult((), 0, 0, b"", False, False, False)

    monkeypatch.setattr("auto_shark.icmp.run_streaming_lines", fake_run)
    summary = triage_icmp_data(root, tmp_path / "tshark.exe")
    assert summary.status == "no-data-payloads"
