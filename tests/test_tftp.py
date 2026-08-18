import json
from pathlib import Path

from auto_shark.engines.stream import StreamProcessResult
from auto_shark.engines.tshark import TsharkCapabilities
from auto_shark.manual_queue import rebuild_manual_queue
from auto_shark.project import create_project
from auto_shark.queries import query_manual_queue
from auto_shark.reporting import collect_report
from auto_shark.storage import Database
from auto_shark.tftp import (
    DATA_FIELDS,
    DISCOVERY_FIELDS,
    _DataPacket,
    _reconstruct,
    _Transfer,
    extract_tftp_transfers,
    parse_data_line,
    parse_discovery_line,
    tshark_tftp_data_arguments,
)
from auto_shark.triage import triage_project


def _row(fields: tuple[str, ...], **values: str) -> bytes:
    return "\t".join(f'"{values.get(field, "")}"' for field in fields).encode()


def _discovery(
    frame: int,
    source: str,
    source_port: int,
    destination: str,
    destination_port: int,
    opcode: int,
    **extra: str,
) -> bytes:
    return _row(
        DISCOVERY_FIELDS,
        **{
            "frame.number": str(frame),
            "frame.time_epoch": f"1.{frame}",
            "ip.src": source,
            "ip.dst": destination,
            "udp.srcport": str(source_port),
            "udp.dstport": str(destination_port),
            "tftp.opcode": str(opcode),
            **extra,
        },
    )


def _data(
    frame: int,
    source: str,
    source_port: int,
    destination: str,
    destination_port: int,
    block: int,
    payload: bytes,
) -> bytes:
    raw = b"\x00\x03" + block.to_bytes(2, "big") + payload
    return _row(
        DATA_FIELDS,
        **{
            "frame.number": str(frame),
            "frame.time_epoch": f"1.{frame}",
            "ip.src": source,
            "ip.dst": destination,
            "udp.srcport": str(source_port),
            "udp.dstport": str(destination_port),
            "udp.payload": raw.hex(":"),
        },
    )


def _capabilities() -> TsharkCapabilities:
    return TsharkCapabilities(
        executable="fake-tshark",
        version_line="TShark test",
        fields=tuple(sorted({*DISCOVERY_FIELDS, *DATA_FIELDS})),
        protocols=("tftp", "udp"),
        export_objects=(),
        features={},
        missing_core_fields=(),
        usable=True,
        errors=(),
    )


def _project(tmp_path: Path) -> Path:
    capture = tmp_path / "tftp.pcapng"
    capture.write_bytes(b"pcapng")
    root = tmp_path / "case.auto-shark"
    create_project(capture, root, allow_synced=True)
    return root


def _lines() -> tuple[list[bytes], list[bytes]]:
    discovery = [
        _discovery(
            1,
            "192.0.2.10",
            40000,
            "192.0.2.20",
            69,
            2,
            **{
                "tftp.destination_file": "instructions.txt",
                "tftp.type": "octet",
            },
        ),
        _discovery(
            2,
            "192.0.2.20",
            50000,
            "192.0.2.10",
            40000,
            4,
            **{"tftp.block": "0", "tftp.request_frame": "1"},
        ),
        _discovery(
            10,
            "192.0.2.10",
            40001,
            "192.0.2.20",
            69,
            1,
            **{"tftp.source_file": "note.txt", "tftp.type": "octet"},
        ),
        _discovery(
            11,
            "192.0.2.20",
            50001,
            "192.0.2.10",
            40001,
            3,
            **{"tftp.block": "1", "tftp.request_frame": "10"},
        ),
        _discovery(
            20,
            "192.0.2.10",
            40002,
            "192.0.2.20",
            69,
            1,
            **{"tftp.source_file": "missing.bin", "tftp.type": "octet"},
        ),
        _discovery(
            21,
            "192.0.2.20",
            50002,
            "192.0.2.10",
            40002,
            5,
            **{
                "tftp.request_frame": "20",
                "tftp.error.code": "1",
                "tftp.error.message": "File not found",
            },
        ),
    ]
    data = [
        _data(
            3,
            "192.0.2.10",
            40000,
            "192.0.2.20",
            50000,
            1,
            b"flag{uploaded-over-tftp}\n",
        ),
        _data(
            11,
            "192.0.2.20",
            50001,
            "192.0.2.10",
            40001,
            1,
            b"downloaded note\n",
        ),
    ]
    return discovery, data


def test_tftp_parsers_and_data_filter() -> None:
    discovery, data = _lines()
    request = parse_discovery_line(discovery[0])
    packet = parse_data_line(data[0])
    assert request.destination_file == "instructions.txt"
    assert request.opcode == 2 and request.destination_port == 69
    assert packet.block == 1 and packet.data.startswith(b"flag{")
    transfer = _Transfer(
        request_frame=1,
        opcode=2,
        filename="instructions.txt",
        mode="octet",
        client="192.0.2.10",
        client_port=40000,
        server="192.0.2.20",
        server_port=50000,
    )
    argv = tshark_tftp_data_arguments(Path("tshark"), Path("cap.pcap"), [transfer])
    display_filter = argv[argv.index("-Y") + 1]
    assert "ip.src == 192.0.2.10" in display_filter
    assert "udp.dstport == 50000" in display_filter


def test_tftp_block_extension_handles_wrap_duplicates_and_conflicts() -> None:
    transfer = _Transfer(1, 1, "large.bin", "octet", "a", 1, "b", 2)
    transfer.packets = [
        _DataPacket(1, "b", 2, "a", 1, 65534, b"a" * 512),
        _DataPacket(2, "b", 2, "a", 1, 65535, b"b" * 512),
        _DataPacket(3, "b", 2, "a", 1, 0, b"c" * 512),
        _DataPacket(4, "b", 2, "a", 1, 1, b"end"),
    ]
    result = _reconstruct(transfer)
    assert [packet.block for packet in result.packets] == [65534, 65535, 0, 1]
    assert result.missing_blocks == 65533
    assert result.status == "partial"

    complete = _Transfer(10, 1, "ok.bin", "octet", "a", 1, "b", 2)
    complete.packets = [
        _DataPacket(11, "b", 2, "a", 1, 1, b"a" * 512),
        _DataPacket(12, "b", 2, "a", 1, 1, b"a" * 512),
        _DataPacket(13, "b", 2, "a", 1, 2, b"end"),
    ]
    result = _reconstruct(complete)
    assert result.status == "complete" and result.duplicate_packets == 1

    complete.packets[1] = _DataPacket(12, "b", 2, "a", 1, 1, b"x" * 512)
    assert _reconstruct(complete).status == "conflicting"


def test_tftp_extract_persists_bidirectional_artifacts_idempotently(
    tmp_path, monkeypatch
) -> None:
    root = _project(tmp_path)
    discovery, data = _lines()
    calls = 0

    def fake_run(argv, callback, **_kwargs):
        nonlocal calls
        selected = discovery if calls % 2 == 0 else data
        calls += 1
        for line in selected:
            callback(line)
        return StreamProcessResult(tuple(argv), 0, len(selected), b"", False, False, False)

    monkeypatch.setattr("auto_shark.tftp.run_streaming_lines", fake_run)
    first = extract_tftp_transfers(
        root, Path("tshark.exe"), capabilities=_capabilities()
    )
    second = extract_tftp_transfers(
        root, Path("tshark.exe"), capabilities=_capabilities()
    )

    assert first == second
    assert [(item.operation, item.status) for item in first.transfers] == [
        ("write", "complete"),
        ("read", "complete"),
        ("read", "server-error"),
    ]
    assert first.transfers[0].output_sha256 == second.transfers[0].output_sha256
    database = Database(root / "project.sqlite")
    with database.connect() as connection:
        counts = {
            table: int(connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0])
            for table in ("evidence", "artifact", "artifact_evidence", "blob", "tool_run")
        }
        locators = [
            json.loads(row[0])
            for row in connection.execute(
                "SELECT locator_json FROM evidence WHERE source_kind='tftp-data' "
                "ORDER BY frame_start"
            )
        ]
    assert counts == {
        "evidence": 3,
        "artifact": 2,
        "artifact_evidence": 2,
        "blob": 2,
        "tool_run": 4,
    }
    assert locators[0]["direction"] == "client-to-server"
    assert locators[2]["status"] == "server-error"

    triage = triage_project(root)
    assert triage.known_matches == 1
    rebuild_manual_queue(root)
    queue = query_manual_queue(root)
    tftp_rules = {
        signal["rule_name"]
        for item in queue.items
        for signal in item["signals"]
        if signal["rule_name"].startswith("tftp-")
    }
    assert tftp_rules == {"tftp-file-transfer", "tftp-incomplete-transfer"}
    report = collect_report(root).payload
    assert report["assessment"]["behaviors"][0]["kind"] == "tftp-file-transfer"
