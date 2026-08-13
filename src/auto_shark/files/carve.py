"""Persist statically carved files, range evidence, and provenance."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Optional

from ..core.ids import EvidenceLocator, evidence_id, stable_id
from ..project import inspect_project
from ..storage import BlobStore, Database
from .signatures import DiscoveryResult, FileCandidate, discover_file_candidates


class _SliceReader:
    def __init__(self, source: BinaryIO, offset: int, length: int) -> None:
        self.source = source
        self.remaining = length
        source.seek(offset)

    def read(self, size: int = -1) -> bytes:
        if self.remaining <= 0:
            return b""
        requested = self.remaining if size < 0 else min(size, self.remaining)
        data = self.source.read(requested)
        self.remaining -= len(data)
        return data


@dataclass(frozen=True)
class CarveSummary:
    project: str
    evidence_scanned: int
    scan_truncated: int
    candidate_limited: int
    carved_files: int
    unique_artifacts: int
    new_artifacts: int
    prefix_regions: int
    trailing_regions: int
    formats: tuple[str, ...]

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, sort_keys=True, indent=2)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _store_slice(store: BlobStore, path: Path, offset: int, length: int):
    with path.open("rb") as source:
        return store.put_stream(_SliceReader(source, offset, length))


def _range_locator(
    *,
    capture_sha256: str,
    source_kind: str,
    parent_public_id: str,
    parent: object,
    offset: int,
    length: int,
) -> EvidenceLocator:
    return EvidenceLocator(
        capture_sha256=capture_sha256,
        source_kind=source_kind,
        frame_start=parent["frame_start"],
        frame_end=parent["frame_end"],
        protocol_message=parent_public_id,
        direction=parent["direction"],
        byte_offset=offset,
        byte_length=length,
    )


def _persist_range_evidence(
    connection: object,
    *,
    locator: EvidenceLocator,
    parent: object,
) -> tuple[int, str]:
    public_id = evidence_id(locator)
    connection.execute(
        "INSERT OR IGNORE INTO evidence "
        "(evidence_id,capture_id,source_kind,frame_start,frame_end,protocol_message_id,"
        "transaction_id,direction,byte_offset,byte_length,blob_id,locator_json) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            public_id,
            parent["capture_id"],
            locator.source_kind,
            parent["frame_start"],
            parent["frame_end"],
            parent["protocol_message_id"],
            parent["transaction_id"],
            parent["direction"],
            locator.byte_offset,
            locator.byte_length,
            parent["blob_id"],
            json.dumps(locator.payload(), ensure_ascii=False, sort_keys=True),
        ),
    )
    internal_id = int(
        connection.execute("SELECT id FROM evidence WHERE evidence_id=?", (public_id,)).fetchone()[
            0
        ]
    )
    return internal_id, public_id


def _persist_scan(
    database: Database,
    parent: object,
    discovery: DiscoveryResult,
    *,
    max_scan_bytes: int,
    max_artifact_bytes: int,
    max_candidates: int,
) -> None:
    status = "complete"
    if discovery.candidate_limit_reached:
        status = "candidate-limit"
    elif discovery.scan_truncated:
        status = "scan-truncated"
    public_id = stable_id(
        "file-scan",
        {
            "parent_evidence_id": parent["evidence_public_id"],
            "max_scan_bytes": max_scan_bytes,
            "max_artifact_bytes": max_artifact_bytes,
            "max_candidates": max_candidates,
        },
    )
    with database.connect() as connection:
        connection.execute(
            "INSERT INTO file_scan "
            "(scan_id,parent_evidence_id,scanned_bytes,parent_bytes,max_scan_bytes,"
            "max_artifact_bytes,max_candidates,candidate_count,status,updated_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT(parent_evidence_id) DO UPDATE SET "
            "scan_id=excluded.scan_id,scanned_bytes=excluded.scanned_bytes,"
            "parent_bytes=excluded.parent_bytes,max_scan_bytes=excluded.max_scan_bytes,"
            "max_artifact_bytes=excluded.max_artifact_bytes,"
            "max_candidates=excluded.max_candidates,candidate_count=excluded.candidate_count,"
            "status=excluded.status,updated_at=excluded.updated_at",
            (
                public_id,
                parent["evidence_db_id"],
                discovery.scanned_bytes,
                discovery.file_length,
                max_scan_bytes,
                max_artifact_bytes,
                max_candidates,
                len(discovery.candidates),
                status,
                _utc_now(),
            ),
        )


def _persist_carve(
    database: Database,
    project_root: Path,
    capture_sha256: str,
    parent: object,
    candidate: FileCandidate,
) -> tuple[str, bool]:
    parent_path = project_root / parent["relative_path"]
    artifact_blob = _store_slice(
        BlobStore(project_root / "blobs"),
        parent_path,
        candidate.start_offset,
        candidate.byte_length,
    )
    relative_path = artifact_blob.path.relative_to(project_root).as_posix()
    carved_locator = _range_locator(
        capture_sha256=capture_sha256,
        source_kind="file-carve",
        parent_public_id=parent["evidence_public_id"],
        parent=parent,
        offset=candidate.start_offset,
        length=candidate.byte_length,
    )
    artifact_public_id = stable_id("artifact", {"sha256": artifact_blob.sha256})
    complete = candidate.structural_status in ("validated", "signature-only")
    with database.connect() as connection:
        connection.execute(
            "INSERT INTO blob (sha256,byte_length,relative_path,media_type,magic_description,"
            "complete,created_at) VALUES (?,?,?,?,?,?,?) ON CONFLICT(sha256) DO UPDATE SET "
            "media_type=coalesce(blob.media_type,excluded.media_type),"
            "magic_description=coalesce(blob.magic_description,excluded.magic_description),"
            "complete=max(blob.complete,excluded.complete)",
            (
                artifact_blob.sha256,
                artifact_blob.byte_length,
                relative_path,
                candidate.media_type,
                candidate.format,
                int(complete),
                _utc_now(),
            ),
        )
        artifact_blob_id = int(
            connection.execute(
                "SELECT id FROM blob WHERE sha256=?", (artifact_blob.sha256,)
            ).fetchone()[0]
        )
        carved_evidence_id, _ = _persist_range_evidence(
            connection, locator=carved_locator, parent=parent
        )
        prefix_evidence_id: Optional[int] = None
        if candidate.prefix_length > 0:
            prefix_locator = _range_locator(
                capture_sha256=capture_sha256,
                source_kind="file-prefix",
                parent_public_id=parent["evidence_public_id"],
                parent=parent,
                offset=0,
                length=candidate.prefix_length,
            )
            prefix_evidence_id, _ = _persist_range_evidence(
                connection, locator=prefix_locator, parent=parent
            )
        trailing_evidence_id: Optional[int] = None
        if candidate.trailing_offset is not None and candidate.trailing_length > 0:
            trailing_locator = _range_locator(
                capture_sha256=capture_sha256,
                source_kind="trailing-data",
                parent_public_id=parent["evidence_public_id"],
                parent=parent,
                offset=candidate.trailing_offset,
                length=candidate.trailing_length,
            )
            trailing_evidence_id, _ = _persist_range_evidence(
                connection, locator=trailing_locator, parent=parent
            )
        existing_artifact = connection.execute(
            "SELECT id FROM artifact WHERE artifact_id=?", (artifact_public_id,)
        ).fetchone()
        is_new_artifact = existing_artifact is None
        connection.execute(
            "INSERT OR IGNORE INTO artifact "
            "(artifact_id,blob_id,source_evidence_id,suggested_name,detected_media_type,"
            "review_state,created_at) VALUES (?,?,?,?,?,'unreviewed',?)",
            (
                artifact_public_id,
                artifact_blob_id,
                carved_evidence_id,
                f"frame-{int(parent['frame_start'] or 0):06d}-offset-"
                f"{candidate.start_offset}{candidate.extension}",
                candidate.media_type,
                _utc_now(),
            ),
        )
        artifact_id = int(
            connection.execute(
                "SELECT id FROM artifact WHERE artifact_id=?", (artifact_public_id,)
            ).fetchone()[0]
        )
        connection.execute(
            "INSERT OR IGNORE INTO artifact_evidence (artifact_id,evidence_id,role) "
            "VALUES (?,?,'carved-from')",
            (artifact_id, carved_evidence_id),
        )
        carve_public_id = stable_id(
            "file-carve",
            {
                "parent_evidence_id": parent["evidence_public_id"],
                "format": candidate.format,
                "start_offset": candidate.start_offset,
                "byte_length": candidate.byte_length,
                "structural_status": candidate.structural_status,
            },
        )
        connection.execute(
            "INSERT OR IGNORE INTO file_carve "
            "(carve_id,parent_evidence_id,carved_evidence_id,artifact_id,prefix_evidence_id,"
            "trailing_evidence_id,format,start_offset,byte_length,structural_status,"
            "validation_detail,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                carve_public_id,
                parent["evidence_db_id"],
                carved_evidence_id,
                artifact_id,
                prefix_evidence_id,
                trailing_evidence_id,
                candidate.format,
                candidate.start_offset,
                candidate.byte_length,
                candidate.structural_status,
                candidate.validation_detail,
                _utc_now(),
            ),
        )
    return candidate.format, is_new_artifact


def carve_project(
    project_path: Path,
    *,
    max_scan_bytes: int = 64 * 1024 * 1024,
    max_artifact_bytes: int = 64 * 1024 * 1024,
    max_candidates_per_evidence: int = 128,
    window_bytes: int = 1024 * 1024,
) -> CarveSummary:
    if (
        min(
            max_scan_bytes,
            max_artifact_bytes,
            max_candidates_per_evidence,
            window_bytes,
        )
        <= 0
    ):
        raise ValueError("file carving limits must be positive")
    project = inspect_project(project_path)
    database = Database(project.root / "project.sqlite")
    database.initialize()
    with database.connect() as connection:
        evidence_rows = connection.execute(
            "SELECT e.id AS evidence_db_id,e.evidence_id AS evidence_public_id,e.capture_id,"
            "e.protocol_message_id,e.transaction_id,e.frame_start,e.frame_end,e.direction,"
            "e.byte_offset,e.byte_length,e.blob_id,b.relative_path,b.byte_length AS blob_length "
            "FROM evidence e JOIN blob b ON b.id=e.blob_id "
            "WHERE e.source_kind IN ('http-body','transform-output','ftp-data','tcp-stream') "
            "AND coalesce(e.byte_offset,0)=0 AND e.byte_length=b.byte_length "
            "ORDER BY e.id"
        ).fetchall()
    carve_count = 0
    new_artifacts = 0
    prefix_count = 0
    trailing_count = 0
    scan_truncated = 0
    candidate_limited = 0
    formats: list[str] = []
    for parent in evidence_rows:
        discovery = discover_file_candidates(
            project.root / parent["relative_path"],
            max_scan_bytes=max_scan_bytes,
            max_artifact_bytes=max_artifact_bytes,
            max_candidates=max_candidates_per_evidence,
            window_bytes=window_bytes,
        )
        _persist_scan(
            database,
            parent,
            discovery,
            max_scan_bytes=max_scan_bytes,
            max_artifact_bytes=max_artifact_bytes,
            max_candidates=max_candidates_per_evidence,
        )
        scan_truncated += int(discovery.scan_truncated)
        candidate_limited += int(discovery.candidate_limit_reached)
        for candidate in discovery.candidates:
            format_name, is_new = _persist_carve(
                database, project.root, project.capture_sha256, parent, candidate
            )
            carve_count += 1
            new_artifacts += int(is_new)
            prefix_count += int(candidate.prefix_length > 0)
            trailing_count += int(candidate.trailing_length > 0)
            formats.append(format_name)
    with database.connect() as connection:
        unique_artifacts = int(connection.execute("SELECT count(1) FROM artifact").fetchone()[0])
    return CarveSummary(
        project=str(project.root),
        evidence_scanned=len(evidence_rows),
        scan_truncated=scan_truncated,
        candidate_limited=candidate_limited,
        carved_files=carve_count,
        unique_artifacts=unique_artifacts,
        new_artifacts=new_artifacts,
        prefix_regions=prefix_count,
        trailing_regions=trailing_count,
        formats=tuple(sorted(set(formats))),
    )
