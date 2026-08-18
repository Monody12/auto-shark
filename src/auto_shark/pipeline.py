"""Persist bounded form transforms and flag candidates with lineage."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .core.ids import EvidenceLocator, candidate_id, evidence_id, stable_id
from .project import inspect_project
from .search import ByteMatch, find_flag_matches
from .storage import BlobStore, Database
from .transforms import decode_recognized, parse_urlencoded_form


@dataclass(frozen=True)
class ScanSummary:
    project: str
    bodies_scanned: int
    form_fields: int
    transforms: int
    candidates: int
    candidate_values: tuple[str, ...]
    carved_files: int
    artifacts: int

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, sort_keys=True, indent=2)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _store_blob(database: Database, project_root: Path, data: bytes, complete: bool = True) -> int:
    blob = BlobStore(project_root / "blobs").put_bytes(data)
    relative_path = blob.path.relative_to(project_root).as_posix()
    with database.connect() as connection:
        connection.execute(
            "INSERT INTO blob (sha256, byte_length, relative_path, complete, created_at) "
            "VALUES (?, ?, ?, ?, ?) ON CONFLICT(sha256) DO UPDATE SET "
            "complete=max(blob.complete, excluded.complete)",
            (blob.sha256, blob.byte_length, relative_path, int(complete), _utc_now()),
        )
        return int(
            connection.execute("SELECT id FROM blob WHERE sha256 = ?", (blob.sha256,)).fetchone()[0]
        )


def _store_evidence(
    database: Database,
    *,
    capture_db_id: int,
    protocol_message_id: int,
    locator: EvidenceLocator,
    blob_id: int,
    text_value: Optional[str],
) -> tuple[int, str]:
    public_id = evidence_id(locator)
    with database.connect() as connection:
        connection.execute(
            "INSERT OR IGNORE INTO evidence "
            "(evidence_id, capture_id, source_kind, frame_start, frame_end, "
            "protocol_message_id, byte_offset, byte_length, field_name, text_value, "
            "blob_id, locator_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                public_id,
                capture_db_id,
                locator.source_kind,
                locator.frame_start,
                locator.frame_end,
                protocol_message_id,
                locator.byte_offset,
                locator.byte_length,
                locator.field_name,
                text_value,
                blob_id,
                json.dumps(locator.payload(), ensure_ascii=False, sort_keys=True),
            ),
        )
        internal_id = int(
            connection.execute(
                "SELECT id FROM evidence WHERE evidence_id = ?", (public_id,)
            ).fetchone()[0]
        )
    return internal_id, public_id


def _store_transform(
    database: Database,
    *,
    parent_evidence_id: int,
    output_evidence_id: int,
    parent_public_id: str,
    name: str,
    version: str,
    parameters: dict[str, object],
    depth: int,
) -> int:
    public_id = stable_id(
        "transform",
        {
            "parent_evidence_id": parent_public_id,
            "name": name,
            "version": version,
            "parameters": parameters,
        },
    )
    with database.connect() as connection:
        connection.execute(
            "INSERT OR IGNORE INTO transform "
            "(transform_id, parent_evidence_id, output_evidence_id, name, version, "
            "parameters_json, depth, status, truncated) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, 'complete', 0)",
            (
                public_id,
                parent_evidence_id,
                output_evidence_id,
                name,
                version,
                json.dumps(parameters, ensure_ascii=False, sort_keys=True),
                depth,
            ),
        )
        return int(
            connection.execute(
                "SELECT id FROM transform WHERE transform_id = ?", (public_id,)
            ).fetchone()[0]
        )


def _store_candidate(
    database: Database,
    *,
    capture_sha256: str,
    match: ByteMatch,
    parent_evidence_db_id: int,
    parent_evidence_public_id: str,
) -> None:
    value = match.value.decode("utf-8", errors="replace")
    normalized = value.strip()
    public_id = candidate_id("flag", normalized)
    lowered = normalized.lower()
    confidence = 0.99 if lowered.startswith("flag{") or lowered.startswith("{flag:") else 0.90
    with database.connect() as connection:
        parent = connection.execute(
            "SELECT capture_id, protocol_message_id, frame_start, frame_end, blob_id "
            "FROM evidence WHERE id = ?",
            (parent_evidence_db_id,),
        ).fetchone()
        if parent is None:
            raise ValueError(f"parent evidence {parent_evidence_db_id} does not exist")
        match_locator = EvidenceLocator(
            capture_sha256=capture_sha256,
            source_kind="flag-match",
            frame_start=parent["frame_start"],
            frame_end=parent["frame_end"],
            protocol_message=parent_evidence_public_id,
            byte_offset=match.offset,
            byte_length=len(match.value),
        )
        match_public_id = evidence_id(match_locator)
        connection.execute(
            "INSERT OR IGNORE INTO evidence "
            "(evidence_id, capture_id, source_kind, frame_start, frame_end, "
            "protocol_message_id, byte_offset, byte_length, text_value, blob_id, "
            "locator_json) VALUES (?, ?, 'flag-match', ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                match_public_id,
                parent["capture_id"],
                parent["frame_start"],
                parent["frame_end"],
                parent["protocol_message_id"],
                match.offset,
                len(match.value),
                value,
                parent["blob_id"],
                json.dumps(match_locator.payload(), ensure_ascii=False, sort_keys=True),
            ),
        )
        match_evidence_db_id = int(
            connection.execute(
                "SELECT id FROM evidence WHERE evidence_id = ?", (match_public_id,)
            ).fetchone()[0]
        )
        connection.execute(
            "INSERT INTO candidate "
            "(candidate_id, kind, raw_value, normalized_value, confidence, rank_score, created_at) "
            "VALUES (?, 'flag', ?, ?, ?, ?, ?) ON CONFLICT(candidate_id) DO UPDATE SET "
            "confidence=max(candidate.confidence, excluded.confidence), "
            "rank_score=max(candidate.rank_score, excluded.rank_score)",
            (public_id, value, normalized, confidence, confidence * 100, _utc_now()),
        )
        candidate_db_id = int(
            connection.execute(
                "SELECT id FROM candidate WHERE candidate_id = ?", (public_id,)
            ).fetchone()[0]
        )
        connection.execute(
            "INSERT OR IGNORE INTO candidate_evidence (candidate_id, evidence_id, role) "
            "VALUES (?, ?, 'direct-match')",
            (candidate_db_id, match_evidence_db_id),
        )


def _scan_evidence(
    database: Database, project_root: Path, capture_sha256: str, evidence_row: object
) -> int:
    blob_path = project_root / evidence_row["relative_path"]
    matches = find_flag_matches(blob_path)
    for match in matches:
        _store_candidate(
            database,
            capture_sha256=capture_sha256,
            match=match,
            parent_evidence_db_id=int(evidence_row["evidence_db_id"]),
            parent_evidence_public_id=str(evidence_row["evidence_public_id"]),
        )
    return len(matches)


def _blob_path_for_evidence(database: Database, evidence_db_id: int) -> str:
    with database.connect() as connection:
        row = connection.execute(
            "SELECT b.relative_path FROM evidence e JOIN blob b ON b.id=e.blob_id WHERE e.id=?",
            (evidence_db_id,),
        ).fetchone()
    if row is None:
        raise ValueError(f"evidence {evidence_db_id} does not reference a blob")
    return str(row[0])


def scan_project(
    project_path: Path,
    *,
    max_transform_output_bytes: int = 16 * 1024 * 1024,
    max_transform_total_bytes: int = 64 * 1024 * 1024,
    max_form_input_bytes: int = 16 * 1024 * 1024,
    with_files: bool = False,
    max_file_scan_bytes: int = 64 * 1024 * 1024,
    max_file_artifact_bytes: int = 64 * 1024 * 1024,
) -> ScanSummary:
    if (
        max_transform_output_bytes <= 0
        or max_transform_total_bytes <= 0
        or max_form_input_bytes <= 0
    ):
        raise ValueError("transform byte budgets must be positive")
    project = inspect_project(project_path)
    database = Database(project.root / "project.sqlite")
    database.initialize()
    with database.connect() as connection:
        capture_db_id = int(
            connection.execute(
                "SELECT id FROM capture WHERE sha256 = ?", (project.capture_sha256,)
            ).fetchone()[0]
        )
        bodies = connection.execute(
            "SELECT pm.id AS protocol_message_id, pm.message_id, pm.representative_frame, "
            "hm.content_type, hb.status AS body_status, e.id AS evidence_db_id, "
            "e.evidence_id AS evidence_public_id, "
            "e.blob_id AS body_blob_id, b.byte_length AS body_byte_length, b.relative_path "
            "FROM http_body hb "
            "JOIN protocol_message pm ON pm.id=hb.protocol_message_id "
            "JOIN http_message hm ON hm.protocol_message_id=pm.id "
            "JOIN evidence e ON e.id=hb.evidence_id JOIN blob b ON b.id=e.blob_id "
            "WHERE hb.extracted_length > 0 ORDER BY pm.representative_frame"
        ).fetchall()
    field_count = 0
    transform_count = 0
    total_output = 0
    for body in bodies:
        _scan_evidence(database, project.root, project.capture_sha256, body)
        if (
            not str(body["content_type"] or "")
            .lower()
            .startswith("application/x-www-form-urlencoded")
        ):
            continue
        if body["body_status"] != "complete":
            continue
        if int(body["body_byte_length"]) > max_form_input_bytes:
            continue
        raw_body = (project.root / body["relative_path"]).read_bytes()
        for field in parse_urlencoded_form(raw_body):
            field_count += 1
            raw_locator = EvidenceLocator(
                capture_sha256=project.capture_sha256,
                source_kind="form-raw-value",
                frame_start=int(body["representative_frame"]),
                frame_end=int(body["representative_frame"]),
                protocol_message=str(body["message_id"]),
                byte_offset=field.raw_offset,
                byte_length=field.raw_length,
                field_name=field.name,
            )
            raw_evidence_id, raw_public_id = _store_evidence(
                database,
                capture_db_id=capture_db_id,
                protocol_message_id=int(body["protocol_message_id"]),
                locator=raw_locator,
                blob_id=int(body["body_blob_id"]),
                text_value=(
                    field.raw_value.decode("utf-8", errors="replace")
                    if len(field.raw_value) <= 4096
                    else None
                ),
            )
            if (
                len(field.decoded_value) > max_transform_output_bytes
                or total_output + len(field.decoded_value) > max_transform_total_bytes
            ):
                continue
            total_output += len(field.decoded_value)
            decoded_blob_id = _store_blob(database, project.root, field.decoded_value)
            decoded_locator = EvidenceLocator(
                capture_sha256=project.capture_sha256,
                source_kind="transform-output",
                frame_start=int(body["representative_frame"]),
                frame_end=int(body["representative_frame"]),
                protocol_message=raw_public_id,
                byte_length=len(field.decoded_value),
                field_name=field.name,
            )
            decoded_evidence_id, decoded_public_id = _store_evidence(
                database,
                capture_db_id=capture_db_id,
                protocol_message_id=int(body["protocol_message_id"]),
                locator=decoded_locator,
                blob_id=decoded_blob_id,
                text_value=(
                    field.decoded_value.decode("utf-8", errors="replace")
                    if len(field.decoded_value) <= 4096
                    else None
                ),
            )
            _store_transform(
                database,
                parent_evidence_id=raw_evidence_id,
                output_evidence_id=decoded_evidence_id,
                parent_public_id=raw_public_id,
                name="url-form-value",
                version="1",
                parameters={"plus_as_space": True},
                depth=1,
            )
            transform_count += 1
            with database.connect() as connection:
                connection.execute(
                    "INSERT OR IGNORE INTO form_field "
                    "(protocol_message_id, ordinal, name, raw_value_evidence_id, "
                    "decoded_value_evidence_id) VALUES (?, ?, ?, ?, ?)",
                    (
                        body["protocol_message_id"],
                        field.ordinal,
                        field.name,
                        raw_evidence_id,
                        decoded_evidence_id,
                    ),
                )
            decoded_row = {
                "relative_path": _blob_path_for_evidence(database, decoded_evidence_id),
                "evidence_db_id": decoded_evidence_id,
                "evidence_public_id": decoded_public_id,
            }
            _scan_evidence(database, project.root, project.capture_sha256, decoded_row)
            recognized = decode_recognized(
                field.decoded_value, max_output_bytes=max_transform_output_bytes
            )
            if (
                recognized is None
                or total_output + len(recognized.output) > max_transform_total_bytes
            ):
                continue
            total_output += len(recognized.output)
            output_blob_id = _store_blob(database, project.root, recognized.output)
            output_locator = EvidenceLocator(
                capture_sha256=project.capture_sha256,
                source_kind="transform-output",
                frame_start=int(body["representative_frame"]),
                frame_end=int(body["representative_frame"]),
                protocol_message=decoded_public_id,
                byte_length=len(recognized.output),
                field_name=field.name,
            )
            output_evidence_id, output_public_id = _store_evidence(
                database,
                capture_db_id=capture_db_id,
                protocol_message_id=int(body["protocol_message_id"]),
                locator=output_locator,
                blob_id=output_blob_id,
                text_value=(
                    recognized.output.decode("utf-8", errors="replace")
                    if len(recognized.output) <= 4096
                    else None
                ),
            )
            _store_transform(
                database,
                parent_evidence_id=decoded_evidence_id,
                output_evidence_id=output_evidence_id,
                parent_public_id=decoded_public_id,
                name=recognized.transform,
                version=recognized.version,
                parameters=recognized.parameters,
                depth=2,
            )
            transform_count += 1
            output_row = {
                "relative_path": _blob_path_for_evidence(database, output_evidence_id),
                "evidence_db_id": output_evidence_id,
                "evidence_public_id": output_public_id,
            }
            _scan_evidence(database, project.root, project.capture_sha256, output_row)
    with database.connect() as connection:
        candidates = tuple(
            str(row[0])
            for row in connection.execute(
                "SELECT normalized_value FROM candidate ORDER BY rank_score DESC, id"
            )
        )
    carved_files = 0
    artifacts = 0
    if with_files:
        from .files.carve import carve_project

        carve = carve_project(
            project.root,
            max_scan_bytes=max_file_scan_bytes,
            max_artifact_bytes=max_file_artifact_bytes,
        )
        carved_files = carve.carved_files
        artifacts = carve.unique_artifacts
    return ScanSummary(
        project=str(project.root),
        bodies_scanned=len(bodies),
        form_fields=field_count,
        transforms=transform_count,
        candidates=len(candidates),
        candidate_values=candidates,
        carved_files=carved_files,
        artifacts=artifacts,
    )
