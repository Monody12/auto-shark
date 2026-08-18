"""Bounded RTP discovery and static G.711 WAV reconstruction."""

from __future__ import annotations

import csv
import json
import sqlite3
import struct
import wave
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from io import BytesIO, StringIO
from pathlib import Path
from uuid import uuid4

from .core.ids import stable_id
from .engines.stream import run_streaming_lines
from .engines.tshark import probe_tshark
from .project import inspect_project
from .storage import BlobStore, Database

RTP_FIELDS = (
    "frame.number",
    "frame.time_epoch",
    "ip.src",
    "ipv6.src",
    "udp.srcport",
    "ip.dst",
    "ipv6.dst",
    "udp.dstport",
    "rtp.ssrc",
    "rtp.p_type",
    "rtp.seq",
    "rtp.timestamp",
    "rtp.payload",
)
RTP_REQUIRED_FIELDS = frozenset(
    {
        "frame.number",
        "udp.srcport",
        "udp.dstport",
        "rtp.ssrc",
        "rtp.p_type",
        "rtp.seq",
        "rtp.timestamp",
        "rtp.payload",
    }
)
CODECS = {0: ("PCMU", "audio/PCMU", 8000), 8: ("PCMA", "audio/PCMA", 8000)}
TRANSFORM_VERSION = "auto-shark.voip-g711/v1"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class RtpPacket:
    frame_number: int
    time_epoch: str
    source: str
    source_port: int
    destination: str
    destination_port: int
    ssrc: int
    payload_type: int
    sequence: int
    timestamp: int
    payload: bytes


@dataclass(frozen=True, order=True)
class _StreamKey:
    source: str
    source_port: int
    destination: str
    destination_port: int
    ssrc: int
    payload_type: int


@dataclass
class _Stream:
    key: _StreamKey
    packets: list[RtpPacket]
    payload_bytes: int = 0


@dataclass(frozen=True)
class VoipArtifact:
    artifact_id: str
    evidence_id: str
    suggested_name: str
    codec: str
    source: str
    source_port: int
    destination: str
    destination_port: int
    ssrc: str
    payload_type: int
    packet_count: int
    duplicate_packets: int
    conflicting_packets: int
    sequence_gap_packets: int
    first_frame: int
    last_frame: int
    wav_bytes: int
    wav_sha256: str
    complete: bool


@dataclass(frozen=True)
class VoipSummary:
    schema_version: str
    project: str
    status: str
    packets_seen: int
    packets_selected: int
    payload_bytes_selected: int
    unsupported_payload_packets: int
    empty_payload_packets: int
    malformed_rows: int
    conflicting_packets: int
    skipped_packet_limit: int
    skipped_stream_limit: int
    skipped_payload_budget: int
    artifacts: tuple[VoipArtifact, ...]
    hints: tuple[str, ...]

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, sort_keys=True, indent=2) + "\n"


def parse_rtp_line(line: bytes) -> RtpPacket:
    text = line.decode("utf-8", errors="strict")
    rows = list(csv.reader(StringIO(text), delimiter="\t", quotechar='"', strict=True))
    if len(rows) != 1 or len(rows[0]) != len(RTP_FIELDS):
        actual = len(rows[0]) if rows else 0
        raise ValueError(f"expected {len(RTP_FIELDS)} RTP columns, received {actual}")
    values = dict(zip(RTP_FIELDS, rows[0]))
    source = values["ip.src"] or values["ipv6.src"]
    destination = values["ip.dst"] or values["ipv6.dst"]
    if not source or not destination:
        raise ValueError("RTP row lacks source or destination address")
    payload_hex = values["rtp.payload"].replace(":", "")
    return RtpPacket(
        frame_number=int(values["frame.number"]),
        time_epoch=values["frame.time_epoch"],
        source=source,
        source_port=int(values["udp.srcport"]),
        destination=destination,
        destination_port=int(values["udp.dstport"]),
        ssrc=int(values["rtp.ssrc"], 0),
        payload_type=int(values["rtp.p_type"]),
        sequence=int(values["rtp.seq"]),
        timestamp=int(values["rtp.timestamp"]),
        payload=bytes.fromhex(payload_hex) if payload_hex else b"",
    )


def tshark_rtp_arguments(executable: Path, capture: Path) -> list[str]:
    arguments = [
        str(executable),
        "-2",
        "-r",
        str(capture),
        "-Y",
        "rtp && !icmp",
        "-T",
        "fields",
        "-E",
        "separator=/t",
        "-E",
        "quote=d",
        "-E",
        "escape=y",
        "-E",
        "occurrence=f",
    ]
    for field in RTP_FIELDS:
        arguments.extend(("-e", field))
    return arguments


class _Collector:
    def __init__(self, max_packets: int, max_streams: int, max_payload_bytes: int) -> None:
        self.max_packets = max_packets
        self.max_streams = max_streams
        self.max_payload_bytes = max_payload_bytes
        self.streams: dict[_StreamKey, _Stream] = {}
        self.packets_seen = 0
        self.packets_selected = 0
        self.payload_bytes_selected = 0
        self.unsupported_payload_packets = 0
        self.empty_payload_packets = 0
        self.malformed_rows = 0
        self.skipped_packet_limit = 0
        self.skipped_stream_limit = 0
        self.skipped_payload_budget = 0

    @property
    def budget_limited(self) -> bool:
        return bool(
            self.skipped_packet_limit or self.skipped_stream_limit or self.skipped_payload_budget
        )

    def add_line(self, line: bytes) -> None:
        self.packets_seen += 1
        try:
            packet = parse_rtp_line(line)
        except (UnicodeError, ValueError):
            self.malformed_rows += 1
            return
        if packet.payload_type not in CODECS:
            self.unsupported_payload_packets += 1
            return
        if not packet.payload:
            self.empty_payload_packets += 1
            return
        key = _StreamKey(
            packet.source,
            packet.source_port,
            packet.destination,
            packet.destination_port,
            packet.ssrc,
            packet.payload_type,
        )
        stream = self.streams.get(key)
        if stream is None:
            if len(self.streams) >= self.max_streams:
                self.skipped_stream_limit += 1
                return
            stream = _Stream(key, [])
            self.streams[key] = stream
        if self.packets_selected >= self.max_packets:
            self.skipped_packet_limit += 1
            return
        if self.payload_bytes_selected + len(packet.payload) > self.max_payload_bytes:
            self.skipped_payload_budget += 1
            return
        stream.packets.append(packet)
        stream.payload_bytes += len(packet.payload)
        self.packets_selected += 1
        self.payload_bytes_selected += len(packet.payload)


def _extended_packets(packets: list[RtpPacket]) -> tuple[list[RtpPacket], int, int, int]:
    if not packets:
        return [], 0, 0, 0
    extended: list[tuple[int, RtpPacket]] = []
    last_sequence = packets[0].sequence
    last_extended = last_sequence
    for packet in packets:
        delta = ((packet.sequence - last_sequence + 32768) % 65536) - 32768
        value = last_extended + delta
        extended.append((value, packet))
        if value > last_extended:
            last_sequence = packet.sequence
            last_extended = value
    unique: dict[int, RtpPacket] = {}
    duplicate_packets = 0
    conflicting_packets = 0
    for value, packet in extended:
        first = unique.setdefault(value, packet)
        if first is packet:
            continue
        if first.payload == packet.payload:
            duplicate_packets += 1
        else:
            conflicting_packets += 1
    ordered = sorted(unique.items())
    missing = sum(
        max(0, current[0] - previous[0] - 1) for previous, current in zip(ordered, ordered[1:])
    )
    return (
        [packet for _, packet in ordered],
        duplicate_packets,
        conflicting_packets,
        missing,
    )


def _mulaw_sample(value: int) -> int:
    value = (~value) & 0xFF
    magnitude = (((value & 0x0F) << 3) + 0x84) << ((value >> 4) & 0x07)
    sample = magnitude - 0x84
    return -sample if value & 0x80 else sample


def _alaw_sample(value: int) -> int:
    value ^= 0x55
    magnitude = (value & 0x0F) << 4
    exponent = (value & 0x70) >> 4
    if exponent == 0:
        magnitude += 8
    elif exponent == 1:
        magnitude += 0x108
    else:
        magnitude = (magnitude + 0x108) << (exponent - 1)
    return magnitude if value & 0x80 else -magnitude


def decode_g711(payload: bytes, payload_type: int) -> bytes:
    if payload_type not in CODECS:
        raise ValueError(f"unsupported G.711 payload type: {payload_type}")
    decoder = _mulaw_sample if payload_type == 0 else _alaw_sample
    output = bytearray(len(payload) * 2)
    for index, value in enumerate(payload):
        struct.pack_into("<h", output, index * 2, decoder(value))
    return bytes(output)


def render_wav(packets: list[RtpPacket], payload_type: int) -> bytes:
    codec = CODECS.get(payload_type)
    if codec is None:
        raise ValueError(f"unsupported G.711 payload type: {payload_type}")
    payload = b"".join(packet.payload for packet in packets)
    pcm = decode_g711(payload, payload_type)
    output = BytesIO()
    with wave.open(output, "wb") as target:
        target.setnchannels(1)
        target.setsampwidth(2)
        target.setframerate(codec[2])
        target.writeframes(pcm)
    return output.getvalue()


def _safe_name(key: _StreamKey, codec: str) -> str:
    source = key.source.replace(":", "_").replace(".", "-")
    destination = key.destination.replace(":", "_").replace(".", "-")
    return (
        f"rtp-{key.ssrc:08x}-{source}_{key.source_port}-to-"
        f"{destination}_{key.destination_port}-{codec.lower()}.wav"
    )


def _store_blob(
    connection: sqlite3.Connection,
    project_root: Path,
    data: bytes,
    *,
    complete: bool,
) -> tuple[int, str, int]:
    blob = BlobStore(project_root / "blobs").put_bytes(data)
    relative = blob.path.relative_to(project_root).as_posix()
    connection.execute(
        "INSERT OR IGNORE INTO blob"
        "(sha256,byte_length,relative_path,media_type,magic_description,complete,created_at) "
        "VALUES(?,?,?,'audio/wav','RIFF WAVE audio',?,?)",
        (blob.sha256, blob.byte_length, relative, int(complete), _now()),
    )
    if complete:
        connection.execute("UPDATE blob SET complete=1 WHERE sha256=?", (blob.sha256,))
    row = connection.execute(
        "SELECT id,sha256,byte_length FROM blob WHERE sha256=?", (blob.sha256,)
    ).fetchone()
    assert row is not None
    return int(row["id"]), str(row["sha256"]), int(row["byte_length"])


def _persist_streams(
    project_root: Path,
    capture_sha256: str,
    streams: list[_Stream],
    *,
    complete: bool,
) -> tuple[VoipArtifact, ...]:
    database = Database(project_root / "project.sqlite")
    artifacts: list[VoipArtifact] = []
    with database.connect() as connection:
        capture_id = int(
            connection.execute(
                "SELECT id FROM capture WHERE sha256=?", (capture_sha256,)
            ).fetchone()[0]
        )
        for stream in sorted(streams, key=lambda item: item.key):
            ordered, duplicate_packets, conflicting_packets, sequence_gap_packets = (
                _extended_packets(stream.packets)
            )
            if not ordered:
                continue
            codec = CODECS[stream.key.payload_type][0]
            wav = render_wav(ordered, stream.key.payload_type)
            stream_complete = complete and sequence_gap_packets == 0 and conflicting_packets == 0
            blob_id, wav_sha256, wav_bytes = _store_blob(
                connection, project_root, wav, complete=stream_complete
            )
            first_frame = min(packet.frame_number for packet in ordered)
            last_frame = max(packet.frame_number for packet in ordered)
            locator = {
                "capture_sha256": capture_sha256,
                "codec": codec,
                "complete": stream_complete,
                "destination": stream.key.destination,
                "destination_port": stream.key.destination_port,
                "duplicate_packets": duplicate_packets,
                "conflicting_packets": conflicting_packets,
                "first_frame": first_frame,
                "last_frame": last_frame,
                "sequence_gap_packets": sequence_gap_packets,
                "packet_count": len(ordered),
                "payload_bytes": sum(len(packet.payload) for packet in ordered),
                "payload_type": stream.key.payload_type,
                "sample_rate": CODECS[stream.key.payload_type][2],
                "source": stream.key.source,
                "source_port": stream.key.source_port,
                "ssrc": f"0x{stream.key.ssrc:08x}",
                "transform": TRANSFORM_VERSION,
            }
            identity = {
                "capture_sha256": capture_sha256,
                "source": stream.key.source,
                "source_port": stream.key.source_port,
                "destination": stream.key.destination,
                "destination_port": stream.key.destination_port,
                "ssrc": stream.key.ssrc,
                "payload_type": stream.key.payload_type,
                "transform": TRANSFORM_VERSION,
            }
            evidence_public_id = stable_id("rtp-audio-evidence", identity)
            connection.execute(
                "INSERT INTO evidence"
                "(evidence_id,capture_id,source_kind,frame_start,frame_end,direction,"
                "byte_offset,byte_length,field_name,blob_id,locator_json) "
                "VALUES(?,?,'rtp-audio',?,?,'source-to-destination',0,?,"
                "'rtp.payload',?,?) ON CONFLICT(evidence_id) DO UPDATE SET "
                "frame_start=excluded.frame_start,frame_end=excluded.frame_end,"
                "byte_length=excluded.byte_length,blob_id=excluded.blob_id,"
                "locator_json=excluded.locator_json",
                (
                    evidence_public_id,
                    capture_id,
                    first_frame,
                    last_frame,
                    wav_bytes,
                    blob_id,
                    json.dumps(locator, sort_keys=True),
                ),
            )
            evidence_db_id = int(
                connection.execute(
                    "SELECT id FROM evidence WHERE evidence_id=?", (evidence_public_id,)
                ).fetchone()[0]
            )
            artifact_public_id = stable_id("rtp-audio-artifact", identity)
            suggested_name = _safe_name(stream.key, codec)
            connection.execute(
                "INSERT INTO artifact"
                "(artifact_id,blob_id,source_evidence_id,suggested_name,declared_media_type,"
                "detected_media_type,review_state,created_at) "
                "VALUES(?,?,?,?,'audio/wav','audio/wav','unreviewed',?) "
                "ON CONFLICT(artifact_id) DO UPDATE SET blob_id=excluded.blob_id,"
                "source_evidence_id=excluded.source_evidence_id,"
                "suggested_name=excluded.suggested_name,"
                "declared_media_type=excluded.declared_media_type,"
                "detected_media_type=excluded.detected_media_type",
                (artifact_public_id, blob_id, evidence_db_id, suggested_name, _now()),
            )
            artifacts.append(
                VoipArtifact(
                    artifact_id=artifact_public_id,
                    evidence_id=evidence_public_id,
                    suggested_name=suggested_name,
                    codec=codec,
                    source=stream.key.source,
                    source_port=stream.key.source_port,
                    destination=stream.key.destination,
                    destination_port=stream.key.destination_port,
                    ssrc=f"0x{stream.key.ssrc:08x}",
                    payload_type=stream.key.payload_type,
                    packet_count=len(ordered),
                    duplicate_packets=duplicate_packets,
                    conflicting_packets=conflicting_packets,
                    sequence_gap_packets=sequence_gap_packets,
                    first_frame=first_frame,
                    last_frame=last_frame,
                    wav_bytes=wav_bytes,
                    wav_sha256=wav_sha256,
                    complete=stream_complete,
                )
            )
    return tuple(artifacts)


def extract_voip_audio(
    project_path: Path,
    tshark: Path,
    *,
    max_packets: int = 100_000,
    max_streams: int = 128,
    max_payload_bytes: int = 64 * 1024 * 1024,
) -> VoipSummary:
    if min(max_packets, max_streams, max_payload_bytes) <= 0:
        raise ValueError("VoIP limits must be positive")
    project = inspect_project(project_path)
    capabilities = probe_tshark(tshark)
    missing = RTP_REQUIRED_FIELDS - set(capabilities.fields)
    if not capabilities.usable or missing:
        raise ValueError("TShark lacks required RTP fields: " + ", ".join(sorted(missing)))
    argv = tshark_rtp_arguments(tshark, project.capture_path)
    collector = _Collector(max_packets, max_streams, max_payload_bytes)
    database = Database(project.root / "project.sqlite")
    run_public_id = uuid4().hex
    started_at = _now()
    with database.connect() as connection:
        connection.execute(
            "INSERT INTO tool_run"
            "(run_id,tool_name,tool_version,argv_json,capability_json,started_at,status) "
            "VALUES(?,?,?,?,?,?,'running')",
            (
                run_public_id,
                "tshark-rtp-audio",
                capabilities.version_line,
                json.dumps(argv, ensure_ascii=False),
                capabilities.to_json(),
                started_at,
            ),
        )
    result = run_streaming_lines(
        argv,
        collector.add_line,
        timeout_seconds=300,
        max_line_bytes=2 * 1024 * 1024,
        stderr_limit=512 * 1024,
    )
    failed = result.timed_out or result.output_limit_exceeded or result.returncode != 0
    status = "failed" if failed else "budget-limited" if collector.budget_limited else "completed"
    with database.connect() as connection:
        connection.execute(
            "UPDATE tool_run SET ended_at=?,status=?,exit_code=?,stderr_text=?,"
            "stderr_truncated=? WHERE run_id=?",
            (
                _now(),
                status,
                result.returncode,
                result.stderr.decode("utf-8", errors="replace"),
                int(result.stderr_truncated),
                run_public_id,
            ),
        )
    if failed:
        raise RuntimeError(f"TShark RTP extraction failed with exit {result.returncode}")
    artifacts = _persist_streams(
        project.root,
        project.capture_sha256,
        list(collector.streams.values()),
        complete=not collector.budget_limited,
    )
    hints = (
        "Review SIP/SDP call setup and both RTP directions before choosing the useful audio.",
        "RTP telephone-event payloads are not audio; review them separately for DTMF digits.",
        "If a reconstructed WAV sounds like modem tones, try an FSK decoder such as "
        "minimodem; 300 baud is a common CTF starting point.",
    )
    return VoipSummary(
        schema_version="auto-shark.voip/v1",
        project=str(project.root),
        status=status,
        packets_seen=collector.packets_seen,
        packets_selected=collector.packets_selected,
        payload_bytes_selected=collector.payload_bytes_selected,
        unsupported_payload_packets=collector.unsupported_payload_packets,
        empty_payload_packets=collector.empty_payload_packets,
        malformed_rows=collector.malformed_rows,
        conflicting_packets=sum(item.conflicting_packets for item in artifacts),
        skipped_packet_limit=collector.skipped_packet_limit,
        skipped_stream_limit=collector.skipped_stream_limit,
        skipped_payload_budget=collector.skipped_payload_budget,
        artifacts=artifacts,
        hints=hints,
    )
