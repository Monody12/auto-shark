"""Persistent human review marks and bounded investigation notes."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from uuid import uuid4

from .core.ids import stable_id
from .project import inspect_project
from .storage import Database

REVIEW_STATES = ("unreviewed", "needs_review", "excluded", "key_evidence")
SUBJECT_KINDS = (
    "artifact",
    "behavior-event",
    "candidate",
    "evidence",
    "finding",
    "manual-task",
)
MAX_PAGE_LIMIT = 1000

_SUBJECT_QUERIES = {
    "artifact": (
        "SELECT 1 FROM artifact a WHERE a.artifact_id=? AND ("
        "EXISTS(SELECT 1 FROM evidence source WHERE source.id=a.source_evidence_id "
        "AND source.capture_id=?) OR EXISTS(SELECT 1 FROM artifact_evidence ae "
        "JOIN evidence linked ON linked.id=ae.evidence_id WHERE ae.artifact_id=a.id "
        "AND linked.capture_id=?))"
    ),
    "behavior-event": "SELECT 1 FROM behavior_event WHERE event_id=? AND capture_id=?",
    "candidate": (
        "SELECT 1 FROM candidate c JOIN candidate_evidence ce ON ce.candidate_id=c.id "
        "JOIN evidence e ON e.id=ce.evidence_id "
        "WHERE c.candidate_id=? AND e.capture_id=? LIMIT 1"
    ),
    "evidence": "SELECT 1 FROM evidence WHERE evidence_id=? AND capture_id=?",
    "finding": (
        "SELECT 1 FROM finding f JOIN finding_evidence fe ON fe.finding_id=f.id "
        "JOIN evidence e ON e.id=fe.evidence_id "
        "WHERE f.finding_id=? AND e.capture_id=? LIMIT 1"
    ),
    "manual-task": "SELECT 1 FROM manual_task WHERE task_id=? AND capture_id=?",
}


@dataclass(frozen=True)
class NotesPage:
    schema_version: str
    offset: int
    limit: int
    total: int
    count: int
    max_body_bytes: int
    subject_kind: Optional[str]
    subject_id: Optional[str]
    items: tuple[dict[str, object], ...]

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, sort_keys=True, indent=2)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _capture_id(connection: sqlite3.Connection, capture_sha256: str) -> int:
    row = connection.execute(
        "SELECT id FROM capture WHERE sha256=?", (capture_sha256,)
    ).fetchone()
    if row is None:
        raise ValueError("project capture is missing from the database")
    return int(row[0])


def _validate_subject_kind(subject_kind: str) -> None:
    if subject_kind not in SUBJECT_KINDS:
        raise ValueError(f"invalid review subject kind: {subject_kind}")


def _subject_exists(
    connection: sqlite3.Connection,
    capture_id: int,
    subject_kind: str,
    subject_id: str,
) -> bool:
    _validate_subject_kind(subject_kind)
    parameters = (
        (subject_id, capture_id, capture_id)
        if subject_kind == "artifact"
        else (subject_id, capture_id)
    )
    return (
        connection.execute(_SUBJECT_QUERIES[subject_kind], parameters).fetchone() is not None
    )


def _require_subject(
    connection: sqlite3.Connection,
    capture_id: int,
    subject_kind: str,
    subject_id: str,
) -> None:
    if not subject_id or not _subject_exists(connection, capture_id, subject_kind, subject_id):
        raise ValueError(f"review subject not found in this project: {subject_kind}/{subject_id}")


def _legacy_note_id(row: sqlite3.Row) -> str:
    return stable_id(
        "investigation-note",
        {
            "created_at": str(row["created_at"]),
            "legacy_row": int(row["id"]),
            "subject_id": str(row["subject_id"]),
            "subject_kind": str(row["subject_kind"]),
        },
    )


def _backfill_notes(connection: sqlite3.Connection, capture_id: int) -> None:
    for row in connection.execute(
        "SELECT n.id,n.subject_kind,n.subject_id,n.body,n.created_at,n.updated_at "
        "FROM note n LEFT JOIN investigation_note current ON current.legacy_note_id=n.id "
        "WHERE current.id IS NULL ORDER BY n.id"
    ):
        subject_kind = str(row["subject_kind"])
        subject_id = str(row["subject_id"])
        if subject_kind not in SUBJECT_KINDS or not _subject_exists(
            connection, capture_id, subject_kind, subject_id
        ):
            continue
        connection.execute(
            "INSERT INTO investigation_note"
            "(note_id,capture_id,subject_kind,subject_id,body,legacy_note_id,"
            "created_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (
                _legacy_note_id(row),
                capture_id,
                subject_kind,
                subject_id,
                str(row["body"]),
                int(row["id"]),
                str(row["created_at"]),
                str(row["updated_at"]),
            ),
        )


def _validate_body(body: str, max_note_bytes: int) -> None:
    if max_note_bytes <= 0:
        raise ValueError("note byte limit must be positive")
    if not body.strip():
        raise ValueError("note body cannot be empty")
    if len(body.encode("utf-8")) > max_note_bytes:
        raise ValueError(f"note body exceeds {max_note_bytes} UTF-8 bytes")


def set_review_mark(
    project_path: Path,
    subject_kind: str,
    subject_id: str,
    state: str,
) -> dict[str, object]:
    if state not in REVIEW_STATES:
        raise ValueError(f"invalid review state: {state}")
    project = inspect_project(project_path)
    database = Database(project.root / "project.sqlite")
    database.initialize()
    updated_at = _now()
    with database.connect() as connection:
        capture_id = _capture_id(connection, project.capture_sha256)
        _require_subject(connection, capture_id, subject_kind, subject_id)
        connection.execute(
            "INSERT INTO review_mark(subject_kind,subject_id,state,updated_at) VALUES(?,?,?,?) "
            "ON CONFLICT(subject_kind,subject_id) DO UPDATE SET "
            "state=excluded.state,updated_at=excluded.updated_at",
            (subject_kind, subject_id, state, updated_at),
        )
    return {
        "schema_version": "auto-shark.review-mark/v1",
        "subject_kind": subject_kind,
        "subject_id": subject_id,
        "state": state,
        "updated_at": updated_at,
    }


def add_note(
    project_path: Path,
    subject_kind: str,
    subject_id: str,
    body: str,
    *,
    max_note_bytes: int = 64 * 1024,
) -> dict[str, object]:
    _validate_body(body, max_note_bytes)
    project = inspect_project(project_path)
    database = Database(project.root / "project.sqlite")
    database.initialize()
    now = _now()
    note_id = stable_id(
        "investigation-note",
        {
            "capture_sha256": project.capture_sha256,
            "nonce": uuid4().hex,
            "subject_id": subject_id,
            "subject_kind": subject_kind,
        },
    )
    with database.connect() as connection:
        capture_id = _capture_id(connection, project.capture_sha256)
        _require_subject(connection, capture_id, subject_kind, subject_id)
        _backfill_notes(connection, capture_id)
        connection.execute(
            "INSERT INTO investigation_note"
            "(note_id,capture_id,subject_kind,subject_id,body,created_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?)",
            (note_id, capture_id, subject_kind, subject_id, body, now, now),
        )
    return {
        "schema_version": "auto-shark.note/v1",
        "note_id": note_id,
        "subject_kind": subject_kind,
        "subject_id": subject_id,
        "body": body,
        "created_at": now,
        "updated_at": now,
    }


def update_note(
    project_path: Path,
    note_id: str,
    body: str,
    *,
    max_note_bytes: int = 64 * 1024,
) -> dict[str, object]:
    _validate_body(body, max_note_bytes)
    project = inspect_project(project_path)
    database = Database(project.root / "project.sqlite")
    database.initialize()
    updated_at = _now()
    with database.connect() as connection:
        capture_id = _capture_id(connection, project.capture_sha256)
        _backfill_notes(connection, capture_id)
        row = connection.execute(
            "SELECT id,subject_kind,subject_id,created_at FROM investigation_note "
            "WHERE note_id=? AND capture_id=?",
            (note_id, capture_id),
        ).fetchone()
        if row is None or not _subject_exists(
            connection, capture_id, str(row["subject_kind"]), str(row["subject_id"])
        ):
            raise ValueError(f"note not found in this project: {note_id}")
        connection.execute(
            "UPDATE investigation_note SET body=?,updated_at=? WHERE id=?",
            (body, updated_at, int(row["id"])),
        )
    return {
        "schema_version": "auto-shark.note/v1",
        "note_id": note_id,
        "subject_kind": str(row["subject_kind"]),
        "subject_id": str(row["subject_id"]),
        "body": body,
        "created_at": str(row["created_at"]),
        "updated_at": updated_at,
    }


def query_notes(
    project_path: Path,
    *,
    subject_kind: Optional[str] = None,
    subject_id: Optional[str] = None,
    offset: int = 0,
    limit: int = 100,
    max_body_bytes: int = 64 * 1024,
) -> NotesPage:
    if subject_kind is not None:
        _validate_subject_kind(subject_kind)
    if offset < 0:
        raise ValueError("note offset cannot be negative")
    if not 0 < limit <= MAX_PAGE_LIMIT:
        raise ValueError(f"note limit must be between 1 and {MAX_PAGE_LIMIT}")
    if max_body_bytes <= 0:
        raise ValueError("note body limit must be positive")
    project = inspect_project(project_path)
    database = Database(project.root / "project.sqlite")
    database.initialize()
    with database.connect() as connection:
        capture_id = _capture_id(connection, project.capture_sha256)
        _backfill_notes(connection, capture_id)
        where = ["capture_id=?"]
        parameters: list[object] = [capture_id]
        if subject_kind is not None:
            where.append("subject_kind=?")
            parameters.append(subject_kind)
        if subject_id is not None:
            where.append("subject_id=?")
            parameters.append(subject_id)
        clause = " AND ".join(where)
        total = int(
            connection.execute(
                f"SELECT count(*) FROM investigation_note WHERE {clause}", parameters
            ).fetchone()[0]
        )
        rows = connection.execute(
            "SELECT note_id,subject_kind,subject_id,body,created_at,updated_at "
            f"FROM investigation_note WHERE {clause} "
            "ORDER BY created_at,note_id LIMIT ? OFFSET ?",
            (*parameters, limit, offset),
        ).fetchall()
        items = []
        for row in rows:
            body = str(row["body"])
            encoded = body.encode("utf-8")
            truncated = len(encoded) > max_body_bytes
            items.append(
                {
                    "note_id": str(row["note_id"]),
                    "subject_kind": str(row["subject_kind"]),
                    "subject_id": str(row["subject_id"]),
                    "body": (
                        encoded[:max_body_bytes].decode("utf-8", errors="ignore")
                        if truncated
                        else body
                    ),
                    "body_bytes": len(encoded),
                    "body_truncated": truncated,
                    "created_at": str(row["created_at"]),
                    "updated_at": str(row["updated_at"]),
                }
            )
    return NotesPage(
        "auto-shark.notes/v1",
        offset,
        limit,
        total,
        len(items),
        max_body_bytes,
        subject_kind,
        subject_id,
        tuple(items),
    )
