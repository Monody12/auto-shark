import itertools
import json
import sys
import textwrap
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import pytest

from auto_shark.plugins import load_plugin_manifest, probe_plugin, run_plugin
from auto_shark.project import create_project
from auto_shark.storage import Database

_UNIQUE = itertools.count()

GOOD_ANALYZER = textwrap.dedent(
    """
    import json
    import shutil
    import sys
    from pathlib import Path

    source = Path(sys.argv[1])
    output_dir = Path(sys.argv[2])
    output_dir.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, output_dir / "copy.bin")
    (output_dir / "result.json").write_text(
        json.dumps({"findings": [{"kind": "test"}]}), encoding="utf-8"
    )
    """
)

SLEEP_ANALYZER = "import time\ntime.sleep(30)\n"
FAIL_ANALYZER = "import sys\nsys.exit(3)\n"
INVALID_JSON_ANALYZER = textwrap.dedent(
    """
    import sys
    from pathlib import Path

    source = Path(sys.argv[1])
    output_dir = Path(sys.argv[2])
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "result.json").write_text("not json", encoding="utf-8")
    """
)
MANY_FILES_ANALYZER = textwrap.dedent(
    """
    import sys
    from pathlib import Path

    source = Path(sys.argv[1])
    output_dir = Path(sys.argv[2])
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "a.bin").write_bytes(b"a" * 10)
    (output_dir / "b.bin").write_bytes(b"b" * 10)
    """
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _manifest(tmp_path: Path, executable: Optional[Path] = None, **overrides) -> Path:
    document = {
        "schema_version": "auto-shark.plugin/v1",
        "name": "fake-analyzer",
        "version": "1.0",
        "executable": str(executable) if executable is not None else sys.executable,
        "capabilities": ["image-analysis"],
        "arguments": ["{input}", "{output_dir}"],
        "timeout_seconds": 30,
        "stdout_limit_bytes": 65536,
        "stderr_limit_bytes": 65536,
        "max_output_files": 8,
        "max_output_file_bytes": 1024 * 1024,
        "max_output_total_bytes": 2 * 1024 * 1024,
        "result_file": "result.json",
    }
    document.update(overrides)
    path = tmp_path / f"manifest-{next(_UNIQUE)}.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _artifact_project(base: Path) -> Path:
    base.mkdir(parents=True, exist_ok=True)
    capture = base / "source.pcap"
    capture.write_bytes(b"pcap")
    root = base / "plugin.auto-shark"
    create_project(capture, root, allow_synced=True)
    blob_bytes = b"jpeg-bytes-here"
    blob_relative = "blobs/artifact.bin"
    (root / blob_relative).write_bytes(blob_bytes)
    database = Database(root / "project.sqlite")
    with database.connect() as connection:
        capture_id = int(connection.execute("SELECT id FROM capture").fetchone()[0])
        connection.execute(
            "INSERT INTO blob"
            "(sha256,byte_length,relative_path,media_type,complete,created_at) "
            "VALUES(?,?,?,?,1,?)",
            (
                __import__("hashlib").sha256(blob_bytes).hexdigest(),
                len(blob_bytes),
                blob_relative,
                "image/jpeg",
                _now(),
            ),
        )
        blob_id = int(connection.execute("SELECT id FROM blob").fetchone()[0])
        connection.execute(
            "INSERT INTO evidence"
            "(evidence_id,capture_id,source_kind,frame_start,frame_end,byte_offset,"
            "byte_length,text_value,blob_id,locator_json) "
            "VALUES('evidence-plugin',?, 'file-carve',1,1,0,?,NULL,?,?)",
            (capture_id, len(blob_bytes), blob_id, "{}"),
        )
        evidence_id = int(
            connection.execute("SELECT id FROM evidence").fetchone()[0]
        )
        connection.execute(
            "INSERT INTO artifact"
            "(artifact_id,blob_id,source_evidence_id,suggested_name,detected_media_type,"
            "review_state,created_at) "
            "VALUES('artifact-plugin',?,?,'sample.jpg','image/jpeg','unreviewed',?)",
            (blob_id, evidence_id, _now()),
        )
    return root


def test_manifest_validation_matrix(tmp_path) -> None:
    analyzer = tmp_path / "analyzer.py"
    analyzer.write_text(GOOD_ANALYZER, encoding="utf-8")
    good = _manifest(tmp_path, analyzer)
    manifest = load_plugin_manifest(good)
    assert manifest.name == "fake-analyzer"
    assert manifest.arguments == ("{input}", "{output_dir}")

    for key, value in (
        ("schema_version", "wrong/v2"),
        ("arguments", ["{output_dir}"]),
        ("capabilities", []),
        ("timeout_seconds", 0),
        ("max_output_files", 0),
        ("result_file", "../escape.json"),
    ):
        with pytest.raises(ValueError):
            load_plugin_manifest(_manifest(tmp_path, analyzer, **{key: value}))
    with pytest.raises(ValueError, match="placeholder"):
        load_plugin_manifest(_manifest(tmp_path, analyzer, arguments=["{input}", "{oops}"]))
    with pytest.raises(FileNotFoundError):
        load_plugin_manifest(tmp_path / "missing.json")


def test_probe_reports_availability(tmp_path) -> None:
    analyzer = tmp_path / "analyzer.py"
    analyzer.write_text(GOOD_ANALYZER, encoding="utf-8")
    probe = probe_plugin(_manifest(tmp_path, analyzer))
    assert probe["schema_version"] == "auto-shark.plugin-probe/v1"
    assert probe["available"] is True
    missing = probe_plugin(_manifest(tmp_path, tmp_path / "nowhere.exe"))
    assert missing["available"] is False
    assert missing["executable_found"] is False


def _run(tmp_path, analyzer_text, artifact_id="artifact-plugin", **overrides):
    root = _artifact_project(tmp_path / f"run-{next(_UNIQUE)}")
    manifest = _analyzer_manifest(tmp_path, analyzer_text, **overrides)
    return root, run_plugin(root, manifest, artifact_id)


def _analyzer_manifest(tmp_path: Path, analyzer_text: str, **overrides) -> Path:
    """Declare the analyzer as [sys.executable, script]; Windows cannot exec .py."""
    script = tmp_path / f"analyzer-{next(_UNIQUE)}.py"
    script.write_text(analyzer_text, encoding="utf-8")
    document = {
        "executable": sys.executable,
        "arguments": [str(script), "{input}", "{output_dir}"],
    }
    document.update(overrides)
    return _manifest(tmp_path, **document)


def test_run_completes_with_hashed_outputs_and_result(tmp_path) -> None:
    root, summary = _run(tmp_path, GOOD_ANALYZER)
    assert summary["schema_version"] == "auto-shark.plugin-run/v1"
    assert summary["status"] == "completed"
    assert summary["exit_code"] == 0
    assert summary["input_sha256"] == __import__("hashlib").sha256(
        b"jpeg-bytes-here"
    ).hexdigest()
    by_name = {item["relative_path"]: item for item in summary["outputs"]}
    assert set(by_name) == {"copy.bin", "result.json"}
    copy_path = Path(summary["job_directory"]) / "output" / "copy.bin"
    assert copy_path.read_bytes() == b"jpeg-bytes-here"
    assert by_name["copy.bin"]["sha256"] == __import__("hashlib").sha256(
        b"jpeg-bytes-here"
    ).hexdigest()
    assert summary["result"] == {"findings": [{"kind": "test"}]}
    assert summary["output_skips"] == []

    database = Database(root / "project.sqlite")
    with database.connect() as connection:
        run_row = connection.execute("SELECT * FROM plugin_run").fetchone()
        detail = connection.execute("SELECT * FROM plugin_run_detail").fetchone()
        outputs = connection.execute("SELECT * FROM plugin_output").fetchall()
        skips = connection.execute("SELECT * FROM plugin_output_skip").fetchall()
        registered = connection.execute("SELECT * FROM plugin_manifest").fetchone()
    assert run_row["status"] == "completed"
    assert run_row["input_artifact_id"] is not None
    assert json.loads(detail["result_json"])["findings"][0]["kind"] == "test"
    assert detail["stdout_truncated"] == 0
    assert len(outputs) == 2
    assert skips == []
    assert registered["name"] == "fake-analyzer"
    assert (Path(run_row["job_directory"]) / "input").is_dir()


def test_run_records_failure_and_timeout(tmp_path) -> None:
    _, failed = _run(tmp_path, FAIL_ANALYZER)
    assert failed["status"] == "failed"
    assert failed["exit_code"] == 3
    assert "exited with code 3" in failed["error"]

    root, timed_out = _run(tmp_path, SLEEP_ANALYZER, timeout_seconds=1)
    assert timed_out["status"] == "timeout"
    assert timed_out["timed_out"] is True


def test_run_output_limits_and_skips(tmp_path) -> None:
    _, limited = _run(tmp_path, MANY_FILES_ANALYZER, max_output_files=1)
    assert len(limited["outputs"]) == 1
    reasons = {item["reason"] for item in limited["output_skips"]}
    assert "file-limit" in reasons

    _, byte_limited = _run(tmp_path, MANY_FILES_ANALYZER, max_output_total_bytes=5)
    assert byte_limited["outputs"] == []
    assert {item["reason"] for item in byte_limited["output_skips"]} == {
        "total-byte-limit",
        "unreadable",
    }


def test_run_invalid_result_json(tmp_path) -> None:
    _, summary = _run(tmp_path, INVALID_JSON_ANALYZER)
    assert summary["result"] is None
    reasons = {item["reason"] for item in summary["output_skips"]}
    assert "result-invalid-json" in reasons
    assert all(item["relative_path"] != "result.json" for item in summary["outputs"])


def test_run_rejects_missing_artifact_and_corrupt_blob(tmp_path) -> None:
    root = _artifact_project(tmp_path)
    manifest = _analyzer_manifest(tmp_path, GOOD_ANALYZER)
    with pytest.raises(ValueError, match="artifact not found"):
        run_plugin(root, manifest, "missing-artifact")

    (root / "blobs" / "artifact.bin").write_bytes(b"tampered")
    with pytest.raises(ValueError, match="verification"):
        run_plugin(root, manifest, "artifact-plugin")

    (root / "blobs" / "artifact.bin").unlink()
    with pytest.raises(FileNotFoundError):
        run_plugin(root, manifest, "artifact-plugin")


def test_cli_plugin_probe_and_run(tmp_path, capsys) -> None:
    from auto_shark import cli

    root = _artifact_project(tmp_path)
    manifest = _analyzer_manifest(tmp_path, GOOD_ANALYZER)
    assert cli.main(["plugin-probe", str(manifest)]) == 0
    assert json.loads(capsys.readouterr().out)["available"] is True
    missing = _manifest(tmp_path, tmp_path / "nowhere.exe")
    assert cli.main(["plugin-probe", str(missing)]) == 2
    assert json.loads(capsys.readouterr().out)["available"] is False

    assert (
        cli.main(["plugin-run", str(root), str(manifest), "--artifact", "artifact-plugin"])
        == 0
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "completed"
    assert payload["schema_version"] == "auto-shark.plugin-run/v1"
