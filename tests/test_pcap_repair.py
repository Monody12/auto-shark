from auto_shark.pcap_repair import (
    PCAP_LE_GLOBAL_HEADER,
    ensure_working_capture,
    is_pcap_like,
    repaired_pcap_bytes,
    zeroed_pcap_header,
)
from auto_shark.project import create_project
from auto_shark.storage import Database


def _zeroed_http_pcap() -> bytes:
    frame = (
        bytes.fromhex("00112233445566778899aabb0800")
        + b"\x45\x00"
        + b"\x00" * 18
        + b"GET /secret HTTP/1.1\r\n\r\n"
    )
    packet_header = (
        b"\x80\x0e\x80i\x00\x00\x00\x00"
        + len(frame).to_bytes(4, "little")
        + len(frame).to_bytes(4, "little")
    )
    return b"\x00" * 24 + packet_header + frame


def test_is_pcap_like_accepts_magic_and_zeroed_header() -> None:
    assert is_pcap_like(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20) is True
    assert is_pcap_like(b"\x0a\x0d\x0d\x0a" + b"\x00" * 20) is True
    assert is_pcap_like(_zeroed_http_pcap()) is True
    assert is_pcap_like(b"ID3\x03\x00\x00\x00\x00\x00\x00") is False
    assert is_pcap_like(b"PK\x03\x04" + b"\x00" * 20) is False


def test_zeroed_pcap_header_is_repaired_without_touching_original(tmp_path) -> None:
    original = _zeroed_http_pcap()
    assert zeroed_pcap_header(original) is True
    repaired = repaired_pcap_bytes(original)
    assert repaired is not None
    assert repaired.startswith(PCAP_LE_GLOBAL_HEADER)
    assert repaired[24:] == original[24:]
    assert original.startswith(b"\x00" * 24)


def test_ensure_working_capture_writes_sidecar_and_finding(tmp_path) -> None:
    capture = tmp_path / "broken.pcap"
    capture.write_bytes(_zeroed_http_pcap())
    root = tmp_path / "broken.auto-shark"
    create_project(capture, root, allow_synced=True)
    working = ensure_working_capture(root)
    assert working == root / "repairs" / "capture.pcap"
    assert working.is_file()
    assert working.read_bytes().startswith(PCAP_LE_GLOBAL_HEADER)
    assert capture.read_bytes().startswith(b"\x00" * 24)
    again = ensure_working_capture(root)
    assert again == working
    with Database(root / "project.sqlite").connect() as connection:
        row = connection.execute(
            "SELECT title FROM finding WHERE detector='pcap-header-repair'"
        ).fetchone()
        assert row is not None
        assert "PCAP" in row[0]
