"""Tests for the generic working-directory adapter used by 7C."""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import auto_shark
from auto_shark.plugins import run_plugin
from auto_shark.project import create_project
from auto_shark.storage import Database

ADAPTER = Path(auto_shark.__file__).resolve().parent / "assets" / "cwd_adapter.py"

INNER_TOOL = """
import sys
from pathlib import Path

assert len(sys.argv) >= 1
Path("produced.bin").write_bytes(b"adapter-payload")
Path("report.txt").write_text("inner tool ran", encoding="utf-8")
sys.exit(0)
"""

INNER_FAIL = "import sys\nsys.exit(5)\n"

INNER_SLEEP = "import time\ntime.sleep(30)\n"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _artifact_project(base: Path) -> Path:
    base.mkdir(parents=True, exist_ok=True)
    capture = base / "source.pcap"
    capture.write_bytes(b"pcap")
    root = base / "adapter.auto-shark"
    create_project(capture, root, allow_synced=True)
    blob_bytes = b"artifact-image-bytes"
    (root / "blobs" / "artifact.bin").write_bytes(blob_bytes)
    import hashlib

    database = Database(root / "project.sqlite")
    with database.connect() as connection:
        capture_id = int(connection.execute("SELECT id FROM capture").fetchone()[0])
        connection.execute(
            "INSERT INTO blob"
            "(sha256,byte_length,relative_path,media_type,complete,created_at) "
            "VALUES(?,?,?,?,1,?)",
            (
                hashlib.sha256(blob_bytes).hexdigest(),
                len(blob_bytes),
                "blobs/artifact.bin",
                "image/jpeg",
                _now(),
            ),
        )
        blob_id = int(connection.execute("SELECT id FROM blob").fetchone()[0])
        connection.execute(
            "INSERT INTO evidence"
            "(evidence_id,capture_id,source_kind,frame_start,frame_end,byte_offset,"
            "byte_length,text_value,blob_id,locator_json) "
            "VALUES('evidence-adapter',?, 'file-carve',1,1,0,?,NULL,?,?)",
            (capture_id, len(blob_bytes), blob_id, "{}"),
        )
        evidence_id = int(
            connection.execute("SELECT id FROM evidence").fetchone()[0]
        )
        connection.execute(
            "INSERT INTO artifact"
            "(artifact_id,blob_id,source_evidence_id,suggested_name,detected_media_type,"
            "review_state,created_at) "
            "VALUES('artifact-adapter',?,?,'pic.jpg','image/jpeg','unreviewed',?)",
            (blob_id, evidence_id, _now()),
        )
    return root


def _manifest(base: Path, inner_script: Path, timeout: str = "20") -> Path:
    document = {
        "schema_version": "auto-shark.plugin/v1",
        "name": "cwd-adapter-tool",
        "version": "1.0",
        "executable": sys.executable,
        "capabilities": ["image-analysis"],
        "arguments": [
            str(ADAPTER),
            timeout,
            sys.executable,
            str(inner_script),
            "{input}",
            "{output_dir}",
        ],
        "timeout_seconds": 60,
        "stdout_limit_bytes": 65536,
        "stderr_limit_bytes": 65536,
        "max_output_files": 8,
        "max_output_file_bytes": 1024 * 1024,
        "max_output_total_bytes": 2 * 1024 * 1024,
        "result_file": None,
    }
    path = base / "adapter-manifest.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _inner(base: Path, text: str) -> Path:
    script = base / "inner.py"
    script.write_text(text, encoding="utf-8")
    return script


def test_adapter_direct_usage_validates_arguments(tmp_path) -> None:
    ok = subprocess.run(
        [sys.executable, str(ADAPTER), "1", sys.executable, "-c", "pass", str(tmp_path)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert ok.returncode == 0
    too_few = subprocess.run(
        [sys.executable, str(ADAPTER), "1"], capture_output=True, text=True, timeout=30
    )
    assert too_few.returncode == 2
    bad_timeout = subprocess.run(
        [sys.executable, str(ADAPTER), "abc", sys.executable, "-c", "pass", str(tmp_path)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert bad_timeout.returncode == 2


def test_adapter_run_collects_inner_tool_outputs(tmp_path) -> None:
    root = _artifact_project(tmp_path)
    manifest = _manifest(tmp_path, _inner(tmp_path, INNER_TOOL))
    summary = run_plugin(root, manifest, "artifact-adapter")
    assert summary["status"] == "completed"
    by_name = {item["relative_path"]: item for item in summary["outputs"]}
    assert set(by_name) == {"produced.bin", "report.txt", "stdout.txt", "stderr.txt"}
    assert (Path(summary["job_directory"]) / "output" / "produced.bin").read_bytes() == (
        b"adapter-payload"
    )
    assert summary["result"] is None


def test_adapter_propagates_failure_and_timeout(tmp_path) -> None:
    root = _artifact_project(tmp_path / "fail")
    manifest = _manifest(tmp_path / "fail", _inner(tmp_path / "fail", INNER_FAIL))
    failed = run_plugin(root, manifest, "artifact-adapter")
    assert failed["status"] == "failed"
    assert failed["exit_code"] == 5

    root2 = _artifact_project(tmp_path / "slow")
    manifest2 = _manifest(tmp_path / "slow", _inner(tmp_path / "slow", INNER_SLEEP))
    timed = run_plugin(root2, manifest2, "artifact-adapter")
    assert timed["status"] == "failed"
    assert timed["exit_code"] == 124
