"""Conservative repair of a zeroed classic-pcap global header.

The original capture file is never overwritten. A repaired copy is written
inside the analysis project and used as the TShark working input.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .core.ids import stable_id
from .project import inspect_project
from .storage import Database

DETECTOR = "pcap-header-repair"
DETECTOR_VERSION = "auto-shark.pcap-header-repair/v1"
# Standard little-endian classic pcap, v2.4, snaplen 65535, LINKTYPE_ETHERNET.
PCAP_LE_GLOBAL_HEADER = bytes.fromhex("d4c3b2a1020004000000000000000000ffff000001000000")
_PCAP_FILE_MAGICS = (
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
    b"\x0a\x0d\x0d\x0a",
)


def zeroed_pcap_header(data: bytes) -> bool:
    """True when the 24-byte global header is zeros and a packet record follows."""

    if len(data) < 40:
        return False
    if data[:24] != b"\x00" * 24:
        return False
    included = int.from_bytes(data[32:36], "little")
    original = int.from_bytes(data[36:40], "little")
    if included != original or included < 14:
        return False
    return 24 + 16 + included <= len(data)


def repaired_pcap_bytes(data: bytes) -> Optional[bytes]:
    if not zeroed_pcap_header(data):
        return None
    return PCAP_LE_GLOBAL_HEADER + data[24:]


def is_pcap_like(data: bytes) -> bool:
    """True for classic pcap, pcapng, or a zeroed header that we can repair."""

    if len(data) >= 4 and data[:4] in _PCAP_FILE_MAGICS:
        return True
    return zeroed_pcap_header(data)


def ensure_working_capture(project_path: Path) -> Path:
    """Return the path TShark should read, repairing a zeroed header if needed."""

    info = inspect_project(project_path)
    manifest_path = info.root / "project.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    capture = manifest.get("capture")
    if not isinstance(capture, dict):
        return info.capture_path
    existing = capture.get("working_path")
    if isinstance(existing, str) and Path(existing).is_file():
        return Path(existing)
    original = Path(str(capture.get("path") or info.capture_path))
    if not original.is_file():
        return info.capture_path
    repaired = repaired_pcap_bytes(original.read_bytes())
    if repaired is None:
        return original
    destination = info.root / "repairs" / "capture.pcap"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(repaired)
    capture["working_path"] = str(destination)
    capture["repair"] = "zeroed-pcap-global-header"
    temporary = manifest_path.with_suffix(".json.tmp")
    temporary.write_text(
        json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, manifest_path)
    _persist_repair_finding(info.root)
    return destination


def _persist_repair_finding(project_root: Path) -> None:
    info = inspect_project(project_root)
    database = Database(project_root / "project.sqlite")
    database.initialize()
    evidence_public_id = stable_id(
        "pcap-header-repair-evidence",
        {"capture_sha256": info.capture_sha256, "repair": "zeroed-pcap-global-header"},
    )
    finding_public_id = stable_id(
        "pcap-header-repair-finding",
        {"capture_sha256": info.capture_sha256, "repair": "zeroed-pcap-global-header"},
    )
    with database.connect() as connection:
        capture_id = int(
            connection.execute(
                "SELECT id FROM capture WHERE sha256=?", (info.capture_sha256,)
            ).fetchone()[0]
        )
        connection.execute(
            "INSERT INTO evidence(evidence_id,capture_id,source_kind,frame_start,frame_end,"
            "byte_offset,byte_length,field_name,text_value,locator_json) "
            "VALUES(?,?,'pcap-global-header',NULL,NULL,0,24,'pcap.global_header',?,?) "
            "ON CONFLICT(evidence_id) DO UPDATE SET text_value=excluded.text_value",
            (
                evidence_public_id,
                capture_id,
                "zeroed-24-byte-global-header",
                json.dumps(
                    {
                        "capture_sha256": info.capture_sha256,
                        "repair": "zeroed-pcap-global-header",
                    },
                    sort_keys=True,
                ),
            ),
        )
        evidence_db_id = int(
            connection.execute(
                "SELECT id FROM evidence WHERE evidence_id=?", (evidence_public_id,)
            ).fetchone()[0]
        )
        connection.execute(
            "INSERT INTO finding(finding_id,detector,detector_version,title,description,"
            "severity,confidence,recommended_action,created_at) VALUES(?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(finding_id) DO UPDATE SET description=excluded.description",
            (
                finding_public_id,
                DETECTOR,
                DETECTOR_VERSION,
                "Repaired zeroed PCAP global header",
                "The first 24 bytes of the capture were all zeros, so TShark cannot open "
                "the original file. Auto-Shark restored a standard Ethernet pcap header "
                "into a project-local copy and left the original bytes unchanged.",
                "high",
                0.9,
                "Continue on the repaired copy. The HTTP body in this challenge pattern "
                "often carries the flag after the header is restored.",
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        finding_db_id = int(
            connection.execute(
                "SELECT id FROM finding WHERE finding_id=?", (finding_public_id,)
            ).fetchone()[0]
        )
        connection.execute(
            "INSERT OR IGNORE INTO finding_evidence(finding_id,evidence_id,role) "
            "VALUES(?,?,?)",
            (finding_db_id, evidence_db_id, "original-header"),
        )
