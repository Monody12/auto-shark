import json
import wave
from io import BytesIO

from auto_shark.engines.stream import StreamProcessResult
from auto_shark.engines.tshark import TsharkCapabilities
from auto_shark.project import create_project
from auto_shark.reporting import collect_report
from auto_shark.storage import Database
from auto_shark.voip import (
    RTP_FIELDS,
    decode_g711,
    extract_voip_audio,
    parse_rtp_line,
    render_wav,
)


def _rtp_line(frame: int, sequence: int, payload: str = "ff7f00") -> bytes:
    values = {
        "frame.number": str(frame),
        "frame.time_epoch": f"1.{frame}",
        "ip.src": "192.0.2.1",
        "ipv6.src": "",
        "udp.srcport": "10000",
        "ip.dst": "192.0.2.2",
        "ipv6.dst": "",
        "udp.dstport": "20000",
        "rtp.ssrc": "0x1234abcd",
        "rtp.p_type": "0",
        "rtp.seq": str(sequence),
        "rtp.timestamp": str(sequence * 160),
        "rtp.payload": payload,
    }
    return "\t".join(f'"{values[field]}"' for field in RTP_FIELDS).encode()


def test_parse_and_decode_g711_payloads() -> None:
    packet = parse_rtp_line(_rtp_line(9, 65535, "ff:7f:00:80"))
    assert packet.frame_number == 9
    assert packet.ssrc == 0x1234ABCD
    assert packet.sequence == 65535
    assert packet.payload == bytes((0xFF, 0x7F, 0x00, 0x80))
    assert decode_g711(packet.payload, 0) == (
        (0).to_bytes(2, "little", signed=True)
        + (0).to_bytes(2, "little", signed=True)
        + (-32124).to_bytes(2, "little", signed=True)
        + (32124).to_bytes(2, "little", signed=True)
    )
    assert decode_g711(bytes((0xD5, 0x55)), 8) == (
        (8).to_bytes(2, "little", signed=True) + (-8).to_bytes(2, "little", signed=True)
    )


def test_render_wav_is_mono_8khz_pcm() -> None:
    packets = [parse_rtp_line(_rtp_line(1, 10)), parse_rtp_line(_rtp_line(2, 11))]
    data = render_wav(packets, 0)
    with wave.open(BytesIO(data), "rb") as source:
        assert source.getnchannels() == 1
        assert source.getsampwidth() == 2
        assert source.getframerate() == 8000
        assert source.getnframes() == 6


def test_extract_voip_audio_persists_idempotent_traceable_artifact(tmp_path, monkeypatch) -> None:
    capture = tmp_path / "voice.pcap"
    capture.write_bytes(b"pcap")
    root = tmp_path / "voice.auto-shark"
    create_project(capture, root, allow_synced=True)
    capabilities = TsharkCapabilities(
        executable="fake-tshark",
        version_line="TShark test",
        fields=RTP_FIELDS,
        protocols=("rtp",),
        export_objects=(),
        features={},
        missing_core_fields=(),
        usable=True,
        errors=(),
    )
    monkeypatch.setattr("auto_shark.voip.probe_tshark", lambda _path: capabilities)

    def fake_run(argv, on_line, **_kwargs):
        for line in (_rtp_line(10, 65535), _rtp_line(11, 0), _rtp_line(12, 0)):
            on_line(line)
        return StreamProcessResult(tuple(argv), 0, 3, b"", False, False, False)

    monkeypatch.setattr("auto_shark.voip.run_streaming_lines", fake_run)
    executable = tmp_path / "tshark.exe"
    executable.write_bytes(b"")

    first = extract_voip_audio(root, executable)
    second = extract_voip_audio(root, executable)

    assert first.status == second.status == "completed"
    assert first.packets_seen == first.packets_selected == 3
    assert len(first.artifacts) == 1
    artifact = first.artifacts[0]
    assert artifact.packet_count == 2
    assert artifact.duplicate_packets == 1
    assert artifact.conflicting_packets == 0
    assert artifact.sequence_gap_packets == 0
    assert artifact.first_frame == 10 and artifact.last_frame == 11
    assert artifact.wav_sha256 == second.artifacts[0].wav_sha256
    with Database(root / "project.sqlite").connect() as connection:
        assert connection.execute("SELECT count(*) FROM artifact").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM evidence").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM blob").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM tool_run").fetchone()[0] == 2
        evidence = connection.execute(
            "SELECT source_kind,frame_start,frame_end,locator_json FROM evidence"
        ).fetchone()
    assert evidence["source_kind"] == "rtp-audio"
    assert (evidence["frame_start"], evidence["frame_end"]) == (10, 11)
    locator = json.loads(evidence["locator_json"])
    assert locator["transform"] == "auto-shark.voip-g711/v1"
    assert locator["ssrc"] == "0x1234abcd"
    report = collect_report(root).payload
    assert report["assessment"]["artifact_summary"]["audio"] == 1
    assert any("audio artifact" in line for line in report["assessment"]["suggested_focus"])


def test_extract_voip_audio_marks_conflicting_sequence_payload_incomplete(
    tmp_path, monkeypatch
) -> None:
    capture = tmp_path / "conflict.pcap"
    capture.write_bytes(b"pcap")
    root = tmp_path / "conflict.auto-shark"
    create_project(capture, root, allow_synced=True)
    capabilities = TsharkCapabilities(
        executable="fake-tshark",
        version_line="TShark test",
        fields=RTP_FIELDS,
        protocols=("rtp",),
        export_objects=(),
        features={},
        missing_core_fields=(),
        usable=True,
        errors=(),
    )
    monkeypatch.setattr("auto_shark.voip.probe_tshark", lambda _path: capabilities)

    def fake_run(argv, on_line, **_kwargs):
        for line in (
            _rtp_line(10, 7, "ff7f00"),
            _rtp_line(11, 7, "000000"),
            _rtp_line(12, 8, "ff7f00"),
        ):
            on_line(line)
        return StreamProcessResult(tuple(argv), 0, 3, b"", False, False, False)

    monkeypatch.setattr("auto_shark.voip.run_streaming_lines", fake_run)
    executable = tmp_path / "tshark.exe"
    executable.write_bytes(b"")

    summary = extract_voip_audio(root, executable)

    assert summary.status == "completed"
    assert summary.conflicting_packets == 1
    artifact = summary.artifacts[0]
    assert artifact.packet_count == 2
    assert artifact.duplicate_packets == 0
    assert artifact.conflicting_packets == 1
    assert artifact.complete is False
    with Database(root / "project.sqlite").connect() as connection:
        evidence = connection.execute("SELECT locator_json FROM evidence").fetchone()
        blob_complete = connection.execute("SELECT complete FROM blob").fetchone()[0]
    assert json.loads(evidence["locator_json"])["conflicting_packets"] == 1
    assert blob_complete == 0
