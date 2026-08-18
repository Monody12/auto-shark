"""Self-contained offline report and bounded evidence-directory export."""

from __future__ import annotations

import hashlib
import html
import json
import os
import shutil
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

from .project import inspect_project
from .reporting import ReportLimits, collect_report
from .storage import Database

MAX_EVIDENCE_ITEMS = 10_000
MAX_EVIDENCE_ITEM_BYTES = 64 * 1024 * 1024
MAX_EVIDENCE_TOTAL_BYTES = 256 * 1024 * 1024


@dataclass(frozen=True)
class ExportLimits:
    include_evidence: bool = True
    max_evidence_items: int = 1000
    max_evidence_item_bytes: int = 16 * 1024 * 1024
    max_evidence_total_bytes: int = 64 * 1024 * 1024

    def validate(self) -> None:
        if not self.include_evidence:
            return
        if not 0 < self.max_evidence_items <= MAX_EVIDENCE_ITEMS:
            raise ValueError(
                f"evidence item limit must be between 1 and {MAX_EVIDENCE_ITEMS}"
            )
        if not 0 < self.max_evidence_item_bytes <= MAX_EVIDENCE_ITEM_BYTES:
            raise ValueError(
                "evidence item byte limit must be between 1 and "
                f"{MAX_EVIDENCE_ITEM_BYTES}"
            )
        if not 0 < self.max_evidence_total_bytes <= MAX_EVIDENCE_TOTAL_BYTES:
            raise ValueError(
                "evidence total byte limit must be between 1 and "
                f"{MAX_EVIDENCE_TOTAL_BYTES}"
            )


@dataclass(frozen=True)
class ExportSummary:
    schema_version: str
    directory: str
    report_sha256: str
    html_sha256: str
    evidence_items: int
    evidence_bytes: int
    evidence_skips: int
    files: tuple[dict[str, object], ...]

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, sort_keys=True, indent=2) + "\n"


def _hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_blob_path(root: Path, relative_path: str) -> Optional[Path]:
    path = (root / relative_path).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError:
        return None
    return path


def _esc(value: object) -> str:
    return html.escape("" if value is None else str(value), quote=True)


_CSS = (
    "body{font:14px system-ui,sans-serif;margin:2rem auto;max-width:1100px;"
    "color:#202124;background:#fff;padding:0 1rem;}"
    "h1{font-size:1.5rem;}h2{font-size:1.15rem;margin-top:2rem;"
    "border-bottom:2px solid #1a73e8;padding-bottom:.2rem;}"
    "table{border-collapse:collapse;width:100%;margin:.5rem 0 1rem;}"
    "th,td{border:1px solid #d8dadd;padding:.35rem .6rem;text-align:left;"
    "vertical-align:top;word-break:break-all;}"
    "th{background:#f1f3f4;}tr:nth-child(even) td{background:#fafbfc;}"
    "ul{margin:.3rem 0 1rem;}.muted{color:#5f6368;}"
    "pre{white-space:pre-wrap;background:#f5f6f7;padding:1rem;"
    "border:1px solid #d8dadd;}details{margin-top:2rem;}"
)


def _table(headers: tuple, rows) -> str:
    if not rows:
        return "<p class='muted'>(none)</p>"
    parts = [
        "<table>",
        "<tr>" + "".join(f"<th>{_esc(header)}</th>" for header in headers) + "</tr>",
    ]
    for row in rows:
        parts.append("<tr>" + "".join(f"<td>{_esc(cell)}</td>" for cell in row) + "</tr>")
    parts.append("</table>")
    return "".join(parts)


def _html_report(report_json: str) -> bytes:
    payload = json.loads(report_json)
    capture = payload.get("capture", {})
    parts = [
        "<!doctype html>\n",
        '<html lang="en"><head><meta charset="utf-8">',
        "<title>Auto-Shark report</title>",
        f"<style>{_CSS}</style></head><body>",
        "<h1>Auto-Shark offline report</h1>",
        "<p class='muted'>Self-contained evidence report: no network resources, no "
        "scripts. The machine-readable JSON is embedded at the bottom.</p>",
        "<h2>Capture</h2>",
        _table(
            ("Field", "Value"),
            [
                ("Source", capture.get("source_name")),
                ("Size (bytes)", capture.get("byte_length")),
                ("SHA-256", capture.get("sha256")),
                ("Database schema", capture.get("database_schema")),
            ],
        ),
    ]

    def collection_rows(name: str, row_fn) -> list:
        collection = payload.get(name) or {}
        return [row_fn(item) for item in (collection.get("items") or [])]

    assessment = payload.get("assessment") or {}
    behaviors = assessment.get("behaviors") or []
    focus = assessment.get("suggested_focus") or []
    if behaviors or focus:
        parts.append("<h2>Assessment</h2>")
        parts.append(
            _table(
                ("Detected behavior", "Source detector", "Count", "Suggested next step"),
                [
                    (
                        behavior.get("kind"),
                        behavior.get("source"),
                        behavior.get("count"),
                        behavior.get("hint"),
                    )
                    for behavior in behaviors
                ],
            )
        )
        if focus:
            parts.append("<ul>" + "".join(f"<li>{_esc(line)}</li>" for line in focus) + "</ul>")

    parts.append("<h2>Flag candidates</h2>")
    parts.append(
        _table(
            ("Rank", "Kind", "Value", "Confidence"),
            collection_rows(
                "candidates",
                lambda item: (
                    item.get("rank_score"),
                    item.get("kind"),
                    item.get("normalized_value"),
                    item.get("confidence"),
                ),
            ),
        )
    )
    parts.append("<h2>Findings</h2>")
    parts.append(
        _table(
            ("Severity", "Detector", "Title", "Recommended action"),
            collection_rows(
                "findings",
                lambda item: (
                    item.get("severity"),
                    item.get("detector"),
                    item.get("title"),
                    item.get("recommended_action"),
                ),
            ),
        )
    )
    parts.append("<h2>WebShell timeline events</h2>")
    parts.append(
        _table(
            ("Request frame", "Kind", "Target", "Status"),
            collection_rows(
                "events",
                lambda item: (
                    item.get("request_frame"),
                    item.get("event_kind"),
                    item.get("target"),
                    item.get("status"),
                ),
            ),
        )
    )
    parts.append("<h2>Artifacts</h2>")
    parts.append(
        _table(
            ("Name", "Detected type", "Review state"),
            collection_rows(
                "artifacts",
                lambda item: (
                    item.get("suggested_name"),
                    item.get("detected_media_type"),
                    item.get("review_state"),
                ),
            ),
        )
    )
    parts.append("<h2>Manual review queue</h2>")
    parts.append(
        _table(
            ("Priority", "State", "Kind", "Subject"),
            collection_rows(
                "manual_tasks",
                lambda item: (
                    item.get("suggested_priority"),
                    item.get("state"),
                    item.get("task_kind"),
                    f"{item.get('subject_kind')}:{item.get('subject_id')}",
                ),
            ),
        )
    )
    protocols = payload.get("protocols") or {}
    parts.append("<h2>Protocols</h2>")
    parts.append(
        _table(
            ("Protocol", "Frames", "First frame", "Last frame"),
            [
                (
                    item.get("protocol_label"),
                    item.get("frame_count"),
                    item.get("first_frame"),
                    item.get("last_frame"),
                )
                for item in (protocols.get("items") or [])
            ],
        )
    )
    conversations = payload.get("conversations") or {}
    parts.append(
        f"<p class='muted'>Conversations total: {_esc(conversations.get('total'))}</p>"
    )
    parts.append(
        "<details><summary>Full machine-readable report JSON</summary><pre>"
        + html.escape(report_json, quote=False)
        + "</pre></details>"
    )
    parts.append("</body></html>\n")
    return "".join(parts).encode("utf-8")


def _evidence_bytes(
    root: Path, row, max_item_bytes: int
) -> tuple[Optional[bytes], Optional[str]]:
    byte_offset = row["byte_offset"]
    byte_length = row["byte_length"]
    if byte_offset is not None and int(byte_offset) < 0:
        return None, "invalid-offset"
    if byte_length is not None and int(byte_length) < 0:
        return None, "invalid-length"
    if row["blob_id"] is None:
        if row["text_value"] is None:
            return None, "no-stored-bytes"
        data = str(row["text_value"]).encode("utf-8")
        start = int(byte_offset or 0)
        length = int(byte_length) if byte_length is not None else len(data) - start
        if start + length > len(data):
            return None, "range-out-of-bounds"
        data = data[start : start + length]
    else:
        if not bool(row["complete"]):
            return None, "blob-incomplete"
        if row["relative_path"] is None:
            return None, "blob-path-missing"
        path = _safe_blob_path(root, str(row["relative_path"]))
        if path is None:
            return None, "blob-path-escapes-project"
        if not path.is_file():
            return None, "blob-missing"
        start = int(byte_offset or 0)
        length = int(byte_length) if byte_length is not None else int(row["byte_length"])
        if start < 0 or length < 0:
            return None, "invalid-range"
        try:
            with path.open("rb") as stream:
                stream.seek(start)
                data = stream.read(length)
        except OSError:
            return None, "blob-read-failed"
        if len(data) != length:
            return None, "range-out-of-bounds"
    if len(data) > max_item_bytes:
        return None, "item-byte-limit"
    return data, None


def _write_stage_file(stage: Path, relative_path: str, data: bytes) -> dict[str, object]:
    target = stage / relative_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    return {
        "path": relative_path.replace("\\", "/"),
        "byte_length": len(data),
        "sha256": _hash_bytes(data),
    }


def export_bundle(
    project_path: Path,
    output_directory: Path,
    *,
    report_limits: Optional[ReportLimits] = None,
    export_limits: Optional[ExportLimits] = None,
) -> ExportSummary:
    if export_limits is None:
        export_limits = ExportLimits()
    export_limits.validate()
    report = collect_report(project_path, limits=report_limits)
    report_json = report.to_json().encode("utf-8")
    html_bytes = _html_report(report_json.decode("utf-8"))
    project = inspect_project(project_path)
    destination = Path(output_directory).expanduser().resolve()
    parent = destination.parent
    parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() and not destination.is_dir():
        raise ValueError("export destination is not a directory")
    if destination.is_dir() and any(destination.iterdir()):
        raise ValueError("export destination must be new or empty")

    stage = Path(tempfile.mkdtemp(prefix=".auto-shark-export-", dir=str(parent)))
    try:
        files = [
            _write_stage_file(stage, "report.json", report_json),
            _write_stage_file(stage, "report.html", html_bytes),
        ]
        evidence_items = 0
        evidence_bytes = 0
        skips: list[dict[str, object]] = []
        if export_limits.include_evidence:
            database = Database(project.root / "project.sqlite")
            with database.connect() as connection:
                capture_id = int(
                    connection.execute(
                        "SELECT id FROM capture WHERE sha256=?", (project.capture_sha256,)
                    ).fetchone()[0]
                )
                evidence_ids = [
                    str(item["evidence_id"])
                    for item in report.payload["evidence"]["items"][
                        : export_limits.max_evidence_items
                    ]
                ]
                placeholders = ",".join("?" for _ in evidence_ids)
                rows = []
                if evidence_ids:
                    rows = connection.execute(
                        "SELECT e.evidence_id,e.byte_offset,e.byte_length,e.text_value,e.blob_id,"
                        "b.relative_path,b.byte_length blob_bytes,b.complete "
                        "FROM evidence e LEFT JOIN blob b ON b.id=e.blob_id "
                        f"WHERE e.capture_id=? AND e.evidence_id IN ({placeholders}) "
                        "ORDER BY e.evidence_id",
                        (capture_id, *evidence_ids),
                    ).fetchall()
                for row in rows:
                    evidence_id = str(row["evidence_id"])
                    data, reason = _evidence_bytes(
                        project.root, row, export_limits.max_evidence_item_bytes
                    )
                    if reason is not None or data is None:
                        skips.append({"evidence_id": evidence_id, "reason": reason})
                        continue
                    if evidence_bytes + len(data) > export_limits.max_evidence_total_bytes:
                        skips.append({"evidence_id": evidence_id, "reason": "total-byte-limit"})
                        continue
                    relative = f"evidence/{evidence_id}.bin"
                    files.append(_write_stage_file(stage, relative, data))
                    evidence_items += 1
                    evidence_bytes += len(data)
                represented = set(evidence_ids)
                for evidence_id in sorted(represented - {str(row["evidence_id"]) for row in rows}):
                    skips.append({"evidence_id": evidence_id, "reason": "evidence-not-found"})
        manifest = {
            "schema_version": "auto-shark.export/v1",
            "report_schema_version": "auto-shark.report/v1",
            "capture_sha256": project.capture_sha256,
            "include_evidence": export_limits.include_evidence,
            "evidence_items": evidence_items,
            "evidence_bytes": evidence_bytes,
            "evidence_skips": skips,
            "files": sorted(files, key=lambda item: str(item["path"])),
        }
        manifest_bytes = (
            json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
        ).encode("utf-8")
        files.append(_write_stage_file(stage, "manifest.json", manifest_bytes))
        if destination.exists():
            destination.rmdir()
        os.replace(str(stage), str(destination))
        return ExportSummary(
            "auto-shark.export/v1",
            str(destination),
            _hash_bytes(report_json),
            _hash_bytes(html_bytes),
            evidence_items,
            evidence_bytes,
            len(skips),
            tuple(sorted(files, key=lambda item: str(item["path"]))),
        )
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        raise
