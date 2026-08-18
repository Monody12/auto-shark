from auto_shark.engines.stream import StreamProcessResult
from auto_shark.engines.tshark import TsharkCapabilities
from auto_shark.project import create_project
from auto_shark.storage import Database
from auto_shark.usb_hid import USB_HID_FIELDS, parse_usb_hid_line, triage_usb_hid


def _line(frame: int, source: str, data: bytes) -> bytes:
    values = {
        "frame.number": str(frame),
        "usb.src": source,
        "usb.dst": "host",
        "usb.endpoint_address": "0x81",
        "usb.capdata": data.hex(),
    }
    return "\t".join(f'"{values[field]}"' for field in USB_HID_FIELDS).encode()


def test_parse_usb_hid_line() -> None:
    report = parse_usb_hid_line(_line(5, "1.8.1", bytes.fromhex("0000060000000000")))
    assert report.frame == 5
    assert report.source == "1.8.1"
    assert report.data[2] == 6


def test_usb_hid_triage_correlates_keyboard_and_pointer(tmp_path, monkeypatch) -> None:
    capture = tmp_path / "usb.pcap"
    capture.write_bytes(b"pcap")
    root = tmp_path / "usb.auto-shark"
    create_project(capture, root, allow_synced=True)
    capabilities = TsharkCapabilities(
        executable="fake-tshark",
        version_line="TShark test",
        fields=USB_HID_FIELDS,
        protocols=("usb",),
        export_objects=(),
        features={"usb_hid": True},
        missing_core_fields=(),
        usable=True,
        errors=(),
    )
    monkeypatch.setattr("auto_shark.usb_hid.probe_tshark", lambda _path: capabilities)
    keyboard = [
        _line(1, "1.8.1", bytes.fromhex("0000060000000000")),
        _line(2, "1.8.1", bytes(8)),
        _line(3, "1.8.1", bytes.fromhex("0000060000000000")),
        _line(4, "1.8.1", bytes(8)),
    ]
    pointer = []
    for frame in range(10, 40):
        x = 1000 + frame * 20
        y = 2000 + frame * 30
        data = bytes((2, 0xE1)) + x.to_bytes(2, "little") + y.to_bytes(2, "little")
        data += bytes((0, 4, 0, 0))
        pointer.append(_line(frame, "1.7.1", data))
    lines = keyboard + pointer

    def fake_run(argv, on_line, **_kwargs):
        for line in lines:
            on_line(line)
        return StreamProcessResult(tuple(argv), 0, len(lines), b"", False, False, False)

    monkeypatch.setattr("auto_shark.usb_hid.run_streaming_lines", fake_run)
    executable = tmp_path / "tshark.exe"
    executable.write_bytes(b"")

    summary = triage_usb_hid(root, executable)
    assert summary.status == "completed"
    assert summary.correlated_input_devices is True
    assert [item.classification for item in summary.endpoints] == [
        "boot-keyboard-like",
        "absolute-pointer-like",
    ]
    assert summary.endpoints[0].key_events == ("c", "c")
    with Database(root / "project.sqlite").connect() as connection:
        assert connection.execute(
            "SELECT count(*) FROM evidence WHERE source_kind='usb-hid-report-series'"
        ).fetchone()[0] == 2
        assert connection.execute(
            "SELECT count(*) FROM finding WHERE detector='usb-hid-triage'"
        ).fetchone()[0] == 2
        assert connection.execute(
            "SELECT status FROM tool_run ORDER BY id DESC LIMIT 1"
        ).fetchone()[0] == "completed"


def test_usb_hid_reports_report_budget_exhaustion(tmp_path, monkeypatch) -> None:
    capture = tmp_path / "usb-budget.pcap"
    capture.write_bytes(b"pcap")
    root = tmp_path / "usb-budget.auto-shark"
    create_project(capture, root, allow_synced=True)
    capabilities = TsharkCapabilities(
        executable="fake-tshark",
        version_line="TShark test",
        fields=USB_HID_FIELDS,
        protocols=("usb",),
        export_objects=(),
        features={"usb_hid": True},
        missing_core_fields=(),
        usable=True,
        errors=(),
    )
    monkeypatch.setattr("auto_shark.usb_hid.probe_tshark", lambda _path: capabilities)

    def fake_run(argv, on_line, **_kwargs):
        for frame in range(1, 5):
            on_line(_line(frame, "1.8.1", bytes(8)))
        return StreamProcessResult(tuple(argv), 0, 4, b"", False, False, False)

    monkeypatch.setattr("auto_shark.usb_hid.run_streaming_lines", fake_run)
    summary = triage_usb_hid(root, tmp_path / "tshark.exe", max_reports=2)

    assert summary.status == "budget-limited"
    assert summary.reports_seen == 4
    assert summary.skipped_report_limit == 2
    with Database(root / "project.sqlite").connect() as connection:
        assert connection.execute(
            "SELECT status FROM tool_run ORDER BY id DESC LIMIT 1"
        ).fetchone()[0] == "budget-limited"
