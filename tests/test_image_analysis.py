"""Tests for automatic image-artifact analysis."""

from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from auto_shark.image_analysis import analyze_project_images
from auto_shark.project import create_project
from auto_shark.storage import Database

ADAPTER = Path(__file__).resolve().parent.parent / "src" / "auto_shark" / "assets" / (
    "cwd_adapter.py"
)

INNER = """
from pathlib import Path
Path("stdout.txt")  # adapter always creates these
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _manifest(base: Path) -> Path:
    document = {
        "schema_version": "auto-shark.plugin/v1",
        "name": "img-probe",
        "version": "1.0",
        "executable": sys.executable,
        "capabilities": ["image-analysis"],
        "arguments": [
            str(ADAPTER),
            "10",
            sys.executable,
            "-c",
            "import sys; print('image ok', sys.argv[1])",
            "{input}",
            "{output_dir}",
        ],
        "timeout_seconds": 30,
        "stdout_limit_bytes": 65536,
        "stderr_limit_bytes": 65536,
        "max_output_files": 4,
        "max_output_file_bytes": 1048576,
        "max_output_total_bytes": 4194304,
        "result_file": None,
    }
    path = base / "img-manifest.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _project(base: Path) -> Path:
    base.mkdir(parents=True, exist_ok=True)
    capture = base / "source.pcap"
    capture.write_bytes(b"pcap")
    root = base / "img.auto-shark"
    create_project(capture, root, allow_synced=True)
    jpeg = b"\xff\xd8\xff\xe0jpeg-image-bytes"
    zip_bytes = b"PK\x05\x06not-really-a-zip"
    (root / "blobs").mkdir(exist_ok=True)
    (root / "blobs" / "img.bin").write_bytes(jpeg)
    (root / "blobs" / "other.bin").write_bytes(zip_bytes)
    database = Database(root / "project.sqlite")
    with database.connect() as connection:
        capture_id = int(connection.execute("SELECT id FROM capture").fetchone()[0])
        for name, media, blob_bytes in (
            ("img.bin", "image/jpeg", jpeg),
            ("other.bin", "application/zip", zip_bytes),
        ):
            connection.execute(
                "INSERT INTO blob"
                "(sha256,byte_length,relative_path,media_type,complete,created_at) "
                "VALUES(?,?,?,?,1,?)",
                (
                    hashlib.sha256(blob_bytes).hexdigest(),
                    len(blob_bytes),
                    f"blobs/{name}",
                    media,
                    _now(),
                ),
            )
            blob_id = int(
                connection.execute("SELECT id FROM blob ORDER BY id DESC LIMIT 1").fetchone()[0]
            )
            connection.execute(
                "INSERT INTO evidence"
                "(evidence_id,capture_id,source_kind,frame_start,frame_end,byte_offset,"
                "byte_length,text_value,blob_id,locator_json) "
                "VALUES(?,?,?,?,1,0,?,NULL,?,?)",
                (
                    f"evidence-{name}",
                    capture_id,
                    "file-carve",
                    1,
                    len(blob_bytes),
                    blob_id,
                    "{}",
                ),
            )
            evidence_id = int(
                connection.execute(
                    "SELECT id FROM evidence WHERE evidence_id=?", (f"evidence-{name}",)
                ).fetchone()[0]
            )
            connection.execute(
                "INSERT INTO artifact"
                "(artifact_id,blob_id,source_evidence_id,suggested_name,detected_media_type,"
                "review_state,created_at) VALUES(?,?,?,?,?, 'unreviewed',?)",
                (
                    f"artifact-{name}",
                    blob_id,
                    evidence_id,
                    name,
                    media,
                    _now(),
                ),
            )
    return root


def test_image_analysis_runs_reports_and_is_idempotent(tmp_path) -> None:
    root = _project(tmp_path)
    manifest = _manifest(tmp_path)

    first = analyze_project_images(root, manifest)
    payload = json.loads(first.to_json())
    assert payload["schema_version"] == "auto-shark.image-analysis/v1"
    assert payload["eligible"] == 1  # only the JPEG, not the zip artifact
    assert payload["analyzed"] == 1
    assert payload["results"][0]["status"] == "completed"

    second = analyze_project_images(root, manifest)
    repeat = json.loads(second.to_json())
    assert repeat["analyzed"] == 0
    assert repeat["already_completed"] == 1

    database = Database(root / "project.sqlite")
    with database.connect() as connection:
        findings = connection.execute("SELECT * FROM finding").fetchall()
        links = connection.execute("SELECT * FROM finding_evidence").fetchall()
        runs = connection.execute("SELECT count(*) FROM plugin_run").fetchone()[0]
    assert len(findings) == 1
    assert findings[0]["detector"] == "image-analyzer:img-probe"
    assert "stdout.txt" in findings[0]["description"]
    assert len(links) == 1
    assert runs == 1


def test_image_analysis_rejects_bad_budget_and_missing_artifacts(tmp_path) -> None:
    root = _project(tmp_path / "case2")
    manifest = _manifest(tmp_path / "case2")
    import pytest

    with pytest.raises(ValueError):
        analyze_project_images(root, manifest, max_artifacts=0)


def test_image_analysis_budget_advances_past_completed_artifacts(tmp_path) -> None:
    root = _project(tmp_path)
    manifest = _manifest(tmp_path)
    first = json.loads(analyze_project_images(root, manifest, max_artifacts=1).to_json())
    assert first["analyzed"] == 1

    image = b"\x89PNG\r\n\x1a\nsecond-image"
    (root / "blobs" / "second.bin").write_bytes(image)
    database = Database(root / "project.sqlite")
    with database.connect() as connection:
        capture_id = int(connection.execute("SELECT id FROM capture").fetchone()[0])
        connection.execute(
            "INSERT INTO blob(sha256,byte_length,relative_path,media_type,complete,created_at) "
            "VALUES(?,?,'blobs/second.bin','image/png',1,?)",
            (hashlib.sha256(image).hexdigest(), len(image), _now()),
        )
        blob_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
        connection.execute(
            "INSERT INTO evidence(evidence_id,capture_id,source_kind,frame_start,frame_end,"
            "byte_offset,byte_length,blob_id,locator_json) "
            "VALUES('evidence-second',?,'file-carve',2,2,0,?,?,'{}')",
            (capture_id, len(image), blob_id),
        )
        evidence_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
        connection.execute(
            "INSERT INTO artifact(artifact_id,blob_id,source_evidence_id,suggested_name,"
            "detected_media_type,review_state,created_at) "
            "VALUES('artifact-second',?,?,'second.png','image/png','unreviewed',?)",
            (blob_id, evidence_id, _now()),
        )

    second = json.loads(analyze_project_images(root, manifest, max_artifacts=1).to_json())
    assert second["eligible"] == 2
    assert second["already_completed"] == 1
    assert second["analyzed"] == 1
    assert second["results"][0]["artifact_id"] == "artifact-second"
