import json
import zlib

from auto_shark.dns import (
    DNS_FIELDS,
    _validated_pngs,
    decode_query_name,
    parse_dns_line,
    triage_dns_tunnels,
)
from auto_shark.engines.stream import StreamProcessResult
from auto_shark.engines.tshark import TsharkCapabilities
from auto_shark.manual_queue import rebuild_manual_queue
from auto_shark.project import create_project
from auto_shark.queries import query_manual_queue
from auto_shark.reporting import collect_report
from auto_shark.storage import Database


def _chunk(kind: bytes, data: bytes) -> bytes:
    crc = zlib.crc32(kind + data) & 0xFFFFFFFF
    return len(data).to_bytes(4, "big") + kind + data + crc.to_bytes(4, "big")


def _png() -> bytes:
    ihdr = (1).to_bytes(4, "big") + (1).to_bytes(4, "big") + bytes((8, 2, 0, 0, 0))
    return b"\x89PNG\r\n\x1a\n" + _chunk(b"IHDR", ihdr) + _chunk(b"IEND", b"")


def _line(frame: int, name: str) -> bytes:
    values = {
        "frame.number": str(frame),
        "frame.time_epoch": f"1.{frame}",
        "ip.src": "192.0.2.10",
        "ipv6.src": "",
        "ip.dst": "192.0.2.53",
        "ipv6.dst": "",
        "udp.stream": "0",
        "dns.qry.name": name,
    }
    return "\t".join(f'"{values[field]}"' for field in DNS_FIELDS).encode()


def _encoded_lines() -> list[bytes]:
    stream = b"welcome-to-a-bounded-dns-tunnel\n" + _png() + b"end-of-stream"
    payloads = [stream[index : index + 16] for index in range(0, len(stream), 16)]
    lines = []
    for frame, payload in enumerate(payloads, 1):
        header = frame.to_bytes(2, "big") + b"DNSHDR0"
        lines.append(_line(frame, (header + payload).hex() + ".example.test"))
    lines.append(_line(len(lines) + 1, (b"\x00\x01DNSHDR0" + payloads[0]).hex() + ".example.test"))
    return lines


def test_parse_and_classify_encoded_dns_labels() -> None:
    parsed = parse_dns_line(_line(7, "4142434445464748.example.test"))
    assert parsed.frame_number == 7
    assert parsed.source == "192.0.2.10"
    decoded = decode_query_name(parsed.query_name)
    assert decoded == ("hex", "example.test", b"ABCDEFGH", "4142434445464748")
    assert decode_query_name("www.example.test") is None


def test_validated_png_respects_the_total_artifact_budget() -> None:
    png = _png()
    assert _validated_pngs(png, len(png)) == [(0, len(png))]
    assert _validated_pngs(png, len(png) - 1) == []


def test_dns_triage_recovers_only_validated_png_and_builds_queue(tmp_path, monkeypatch) -> None:
    capture = tmp_path / "dns.pcap"
    capture.write_bytes(b"pcap")
    root = tmp_path / "dns.auto-shark"
    create_project(capture, root, allow_synced=True)
    capabilities = TsharkCapabilities(
        executable="fake-tshark",
        version_line="TShark test",
        fields=DNS_FIELDS,
        protocols=("dns",),
        export_objects=(),
        features={},
        missing_core_fields=(),
        usable=True,
        errors=(),
    )
    monkeypatch.setattr("auto_shark.dns.probe_tshark", lambda _path: capabilities)
    lines = _encoded_lines()

    def fake_run(argv, on_line, **_kwargs):
        for line in lines:
            on_line(line)
        return StreamProcessResult(tuple(argv), 0, len(lines), b"", False, False, False)

    monkeypatch.setattr("auto_shark.dns.run_streaming_lines", fake_run)
    executable = tmp_path / "tshark.exe"
    executable.write_bytes(b"")

    first = triage_dns_tunnels(root, executable)
    second = triage_dns_tunnels(root, executable)

    assert first.status == second.status == "completed"
    assert len(first.groups) == 1
    group = first.groups[0]
    assert group.encoding == "hex"
    assert group.base_domain == "example.test"
    assert group.inferred_header_bytes == 9
    assert group.artifact_bytes == len(_png())
    assert group.artifact_sha256 == second.groups[0].artifact_sha256
    with Database(root / "project.sqlite").connect() as connection:
        assert connection.execute("SELECT count(*) FROM artifact").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM evidence").fetchone()[0] == 2
        assert connection.execute("SELECT count(*) FROM tool_run").fetchone()[0] == 2
        locator = json.loads(
            connection.execute(
                "SELECT locator_json FROM evidence WHERE source_kind='dns-label-stream'"
            ).fetchone()[0]
        )
        carved = connection.execute(
            "SELECT byte_offset,byte_length FROM evidence "
            "WHERE source_kind='dns-carved-file'"
        ).fetchone()
    assert locator["ordering"] == "capture-first-seen"
    assert locator["inferred_header_bytes"] == 9
    assert carved["byte_offset"] > 0 and carved["byte_length"] == len(_png())

    rebuild_manual_queue(root)
    queue = query_manual_queue(root)
    assert queue.total == 1
    assert queue.items[0]["signals"][0]["rule_name"] == "suspicious-dns-encoded-labels"
    report = collect_report(root).payload
    assert report["assessment"]["behaviors"][0]["kind"] == "dns-encoded-labels"
    assert report["assessment"]["artifact_summary"]["image"] == 1


def test_dns_triage_does_not_promote_small_or_normal_groups(tmp_path, monkeypatch) -> None:
    capture = tmp_path / "normal.pcap"
    capture.write_bytes(b"pcap")
    root = tmp_path / "normal.auto-shark"
    create_project(capture, root, allow_synced=True)
    capabilities = TsharkCapabilities(
        executable="fake-tshark",
        version_line="TShark test",
        fields=DNS_FIELDS,
        protocols=("dns",),
        export_objects=(),
        features={},
        missing_core_fields=(),
        usable=True,
        errors=(),
    )
    monkeypatch.setattr("auto_shark.dns.probe_tshark", lambda _path: capabilities)
    lines = [_line(1, "www.example.test"), _line(2, "4142434445464748.example.test")]

    def fake_run(argv, on_line, **_kwargs):
        for line in lines:
            on_line(line)
        return StreamProcessResult(tuple(argv), 0, len(lines), b"", False, False, False)

    monkeypatch.setattr("auto_shark.dns.run_streaming_lines", fake_run)
    executable = tmp_path / "tshark.exe"
    executable.write_bytes(b"")
    summary = triage_dns_tunnels(root, executable)
    assert summary.groups == ()
    with Database(root / "project.sqlite").connect() as connection:
        assert connection.execute("SELECT count(*) FROM evidence").fetchone()[0] == 0
        assert connection.execute("SELECT count(*) FROM artifact").fetchone()[0] == 0
