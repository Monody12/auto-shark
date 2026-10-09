"""Concatenate SNMP variable-binding strings into scannable evidence.

Classic CTF pattern (e.g. 2016cff simple_snmp): the exfiltrated data rides
in OctetString variable bindings — one fragment per GET/SET — including the
flag itself or an encoding of it. Values are concatenated per frame into one
blob stored as ``snmp-strings`` evidence so triage/transform stages pick it
up automatically.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from .core.ids import stable_id
from .engines.stream import run_streaming_lines
from .engines.tshark import probe_tshark
from .project import inspect_project
from .storage import BlobStore, Database

SNMP_DETECTOR_VERSION = "snmp-strings/v1"
SNMP_MAX_FRAMES = 100_000
SNMP_MAX_BYTES = 16 * 1024 * 1024


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class SnmpStringsSummary:
    detector_version: str
    project: str
    status: str
    frames: int
    value_bytes: int
    evidence_id: str | None
    notes: tuple[str, ...]

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, sort_keys=True)


def triage_snmp_strings(
    project_path: Path,
    tshark: Path,
    *,
    max_frames: int = SNMP_MAX_FRAMES,
    max_bytes: int = SNMP_MAX_BYTES,
) -> SnmpStringsSummary:
    if min(max_frames, max_bytes) <= 0:
        raise ValueError("SNMP string limits must be positive")
    project = inspect_project(project_path)
    capabilities = probe_tshark(tshark)
    if not capabilities.usable or "snmp.value.octets" not in capabilities.fields:
        return SnmpStringsSummary(
            SNMP_DETECTOR_VERSION,
            str(project.root),
            "unavailable",
            0,
            0,
            None,
            ("TShark does not expose the snmp.value.octets field.",),
        )
    argv = [
        str(tshark),
        "-r",
        str(project.capture_path),
        "-Y",
        "snmp || udp.port == 161",
        "-T",
        "fields",
        "-E",
        "separator=/t",
        "-E",
        "occurrence=a",
        "-e",
        "frame.number",
        "-e",
        "snmp.community",
        "-e",
        "snmp.value.octets",
    ]
    frames: list[tuple[int, str, bytes]] = []
    truncated = False
    total = 0

    def consume(line: bytes) -> None:
        nonlocal truncated, total
        if not line or len(frames) >= max_frames:
            if line:
                truncated = True
            return
        parts = line.decode("utf-8", errors="replace").split("\t")
        if len(parts) < 3 or not parts[2].strip():
            return
        try:
            frame = int(parts[0])
        except ValueError:
            return
        community = parts[1].strip().split(",")[0]
        payload = bytearray()
        for octets in parts[2].split(","):
            octets = octets.strip()
            if not octets:
                continue
            try:
                payload += bytes.fromhex(octets)
            except ValueError:
                continue
        if not payload:
            return
        if total + len(payload) > max_bytes:
            truncated = True
            return
        frames.append((frame, community, bytes(payload)))
        total += len(payload)

    run_streaming_lines(
        argv,
        consume,
        timeout_seconds=300,
        max_line_bytes=1024 * 1024,
        stderr_limit=256 * 1024,
    )
    if not frames:
        return SnmpStringsSummary(
            SNMP_DETECTOR_VERSION, str(project.root), "no-snmp-strings", 0, 0, None, ()
        )
    document = b"".join(
        f"frame={frame} community={community} {payload.decode('utf-8', errors='replace')}\n".encode(
            "utf-8", errors="replace"
        )
        for frame, community, payload in frames
    )
    store = BlobStore(project.root / "blobs")
    blob = store.put_bytes(document)
    relative_path = blob.path.relative_to(project.root).as_posix()
    evidence_public_id = stable_id(
        "snmp-strings-evidence", {"capture_sha256": project.capture_sha256}
    )
    preview = document[:256].decode("utf-8", errors="replace")
    locator = {
        "capture_sha256": project.capture_sha256,
        "detector": SNMP_DETECTOR_VERSION,
        "frames": len(frames),
        "value_bytes": len(document),
        "truncated": truncated,
    }
    database = Database(project.root / "project.sqlite")
    with database.connect() as connection:
        capture_id = int(
            connection.execute(
                "SELECT id FROM capture WHERE sha256=?", (project.capture_sha256,)
            ).fetchone()[0]
        )
        connection.execute(
            "INSERT INTO blob(sha256,byte_length,relative_path,media_type,magic_description,"
            "complete,created_at) VALUES (?,?,?,?,?,1,?) "
            "ON CONFLICT(sha256) DO NOTHING",
            (
                blob.sha256,
                len(document),
                relative_path,
                None,
                "concatenated SNMP variable-binding strings",
                _now(),
            ),
        )
        blob_id = int(
            connection.execute(
                "SELECT id FROM blob WHERE sha256=?", (blob.sha256,)
            ).fetchone()[0]
        )
        connection.execute(
            "INSERT INTO evidence(evidence_id,capture_id,source_kind,frame_start,frame_end,"
            "direction,byte_offset,byte_length,field_name,text_value,blob_id,locator_json) "
            "VALUES(?,?,'snmp-strings',?,?,NULL,0,?,NULL,?,?,?) "
            "ON CONFLICT(evidence_id) DO UPDATE SET frame_start=excluded.frame_start,"
            "frame_end=excluded.frame_end,byte_length=excluded.byte_length,"
            "text_value=excluded.text_value,blob_id=excluded.blob_id,"
            "locator_json=excluded.locator_json",
            (
                evidence_public_id,
                capture_id,
                min(frame for frame, _, _ in frames),
                max(frame for frame, _, _ in frames),
                len(document),
                preview,
                blob_id,
                json.dumps(locator, ensure_ascii=False, sort_keys=True),
            ),
        )
    notes = ["run triage to scan the concatenated SNMP strings for candidates"]
    if truncated:
        notes.append("input truncated by configured limits")
    return SnmpStringsSummary(
        SNMP_DETECTOR_VERSION,
        str(project.root),
        "stored" if not truncated else "stored-truncated",
        len(frames),
        len(document),
        evidence_public_id,
        tuple(notes),
    )
