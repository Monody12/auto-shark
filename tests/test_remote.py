import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

from auto_shark.engines.process import ProcessResult
from auto_shark.plugins import load_plugin_manifest
from auto_shark.project import create_project
from auto_shark.remote import (
    RemoteNodeConfig,
    RemoteTransport,
    RemoteTransportError,
    SshTransport,
    find_ssh_tools,
    probe_remote_node,
    run_remote_job,
)
from auto_shark.storage import Database


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class FakeTransport(RemoteTransport):
    """Local filesystem stand-in for a remote node."""

    def __init__(self, root: Path, exit_code: int = 0, timed_out: bool = False) -> None:
        self.root = root
        self.exit_code = exit_code
        self.timed_out = timed_out
        self.commands: list = []
        self.puts: list = []
        self.gets: list = []

    def _local(self, remote_path: str) -> Path:
        if ".." in remote_path:
            raise RemoteTransportError("unsafe remote path")
        return self.root.joinpath(*remote_path.split("/"))

    def make_directory(self, remote_path: str) -> None:
        self._local(remote_path).mkdir(parents=True, exist_ok=True)

    def put_file(self, local_path: Path, remote_path: str) -> None:
        target = self._local(remote_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(local_path.read_bytes())
        self.puts.append(remote_path)

    def get_file(self, remote_path: str, local_path: Path) -> None:
        source = self._local(remote_path)
        if not source.is_file():
            raise RemoteTransportError(f"remote file missing: {remote_path}")
        local_path.parent.mkdir(parents=True, exist_ok=True)
        local_path.write_bytes(source.read_bytes())
        self.gets.append(remote_path)

    def run(self, command, timeout_seconds, stdout_limit, stderr_limit) -> ProcessResult:
        self.commands.append(list(command))
        return ProcessResult(
            argv=tuple(str(item) for item in command),
            returncode=self.exit_code,
            stdout=b"remote-ok\n",
            stderr=b"",
            stdout_truncated=False,
            stderr_truncated=False,
            timed_out=self.timed_out,
            output_limit_exceeded=False,
        )


def _project_with_artifact(base: Path) -> Path:
    base.mkdir(parents=True, exist_ok=True)
    capture = base / "source.pcap"
    capture.write_bytes(b"pcap")
    root = base / "remote.auto-shark"
    create_project(capture, root, allow_synced=True)
    blob_bytes = b"remote-jpeg-bytes"
    (root / "blobs" / "artifact.bin").write_bytes(blob_bytes)
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
            "VALUES('evidence-remote',?, 'file-carve',1,1,0,?,NULL,?,?)",
            (capture_id, len(blob_bytes), blob_id, "{}"),
        )
        evidence_id = int(
            connection.execute("SELECT id FROM evidence").fetchone()[0]
        )
        connection.execute(
            "INSERT INTO artifact"
            "(artifact_id,blob_id,source_evidence_id,suggested_name,detected_media_type,"
            "review_state,created_at) "
            "VALUES('artifact-remote',?,?,'pic.jpg','image/jpeg','unreviewed',?)",
            (blob_id, evidence_id, _now()),
        )
    return root


def _remote_manifest(base: Path, **overrides) -> Path:
    document = {
        "schema_version": "auto-shark.plugin/v1",
        "name": "remote-tool",
        "version": "1.0",
        "executable": "/usr/local/bin/analyze",
        "capabilities": ["image-analysis"],
        "arguments": ["--input", "{input}", "--output-dir", "{output_dir}"],
        "timeout_seconds": 30,
        "stdout_limit_bytes": 65536,
        "stderr_limit_bytes": 65536,
        "max_output_files": 4,
        "max_output_file_bytes": 1024 * 1024,
        "max_output_total_bytes": 2 * 1024 * 1024,
        "result_file": "result.json",
    }
    document.update(overrides)
    path = base / "remote-manifest.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def test_find_ssh_tools_and_config_validation(tmp_path) -> None:
    ssh, sftp = find_ssh_tools(tmp_path / "no-ssh.exe", tmp_path / "no-sftp.exe")
    assert ssh is None and sftp is None
    config = RemoteNodeConfig(
        host="root@node.example",
        ssh_executable=tmp_path / "ssh.exe",
        sftp_executable=tmp_path / "sftp.exe",
    )
    config.validate()
    with pytest.raises(ValueError):
        RemoteNodeConfig(
            host="root@node 'injected'",
            ssh_executable=tmp_path / "ssh.exe",
            sftp_executable=tmp_path / "sftp.exe",
        ).validate()
    with pytest.raises(ValueError):
        RemoteNodeConfig(
            host="root@node.example",
            ssh_executable=tmp_path / "ssh.exe",
            sftp_executable=tmp_path / "sftp.exe",
            remote_root="../escape",
        ).validate()


def test_ssh_transport_argv_and_batch_are_constrained(tmp_path) -> None:
    (tmp_path / "ssh.exe").write_bytes(b"")
    (tmp_path / "sftp.exe").write_bytes(b"")
    transport = SshTransport(
        RemoteNodeConfig(
            host="root@node.example",
            ssh_executable=tmp_path / "ssh.exe",
            sftp_executable=tmp_path / "sftp.exe",
        )
    )
    argv = transport.ssh_argv(["test", "-x", "/usr/local/bin/analyze"])
    assert argv[0].endswith("ssh.exe")
    assert argv[-4:] == ["root@node.example", "test", "-x", "/usr/local/bin/analyze"]
    assert "BatchMode=yes" in argv
    with pytest.raises(ValueError):
        transport.ssh_argv(["test", "-x", "/opt/tool;rm -rf /"])
    batch = transport.sftp_batch_text(
        [("put", r"C:\work\file.bin", ".auto-shark-jobs/j1/input/file.bin")]
    )
    assert batch == 'put "C:/work/file.bin" ".auto-shark-jobs/j1/input/file.bin"\n'
    with pytest.raises(ValueError):
        transport.sftp_batch_text([("get", "../etc/passwd", "x")])


def test_probe_remote_node_rejects_relative_and_reports(tmp_path, monkeypatch) -> None:
    (tmp_path / "ssh.exe").write_bytes(b"")
    (tmp_path / "sftp.exe").write_bytes(b"")
    config = RemoteNodeConfig(
        host="root@node.example",
        ssh_executable=tmp_path / "ssh.exe",
        sftp_executable=tmp_path / "sftp.exe",
    )
    calls = []

    def fake_run(self, command, timeout_seconds, stdout_limit, stderr_limit):
        calls.append(list(command))
        return ProcessResult(
            argv=tuple(command), returncode=0, stdout=b"", stderr=b"",
            stdout_truncated=False, stderr_truncated=False, timed_out=False,
            output_limit_exceeded=False,
        )

    monkeypatch.setattr(SshTransport, "run", fake_run)
    probe = probe_remote_node(config, ["/usr/local/bin/analyze", "relative/tool"])
    assert probe["schema_version"] == "auto-shark.remote-probe/v1"
    assert probe["probes"][0]["available"] is True
    assert probe["probes"][1]["available"] is False
    assert calls[0] == ["test", "-x", "/usr/local/bin/analyze"]
    assert probe["available"] is False


def test_run_remote_job_completes_with_hash_verification(tmp_path) -> None:
    root = _project_with_artifact(tmp_path)
    manifest = _remote_manifest(tmp_path)
    fake_root = tmp_path / "fake-remote"

    def stage_outputs(transport: FakeTransport) -> None:
        job_dirs = list(fake_root.glob(".auto-shark-jobs/*/output"))
        assert len(job_dirs) == 1
        output = job_dirs[0]
        result = {
            "findings": [{"kind": "stego"}],
            "output_files": ["extracted.png"],
        }
        (output / "result.json").write_text(json.dumps(result), encoding="utf-8")
        (output / "extracted.png").write_bytes(b"\x89PNG\r\n\x1a\npayload")

    transport = FakeTransport(fake_root)
    original_put = transport.put_file

    def put_and_stage(local_path: Path, remote_path: str) -> None:
        original_put(local_path, remote_path)
        stage_outputs(transport)

    transport.put_file = put_and_stage  # type: ignore[method-assign]

    summary = run_remote_job(
        root, transport, manifest, "artifact-remote",
        node_name="node-a", remote_root=".auto-shark-jobs",
    )
    assert summary["schema_version"] == "auto-shark.remote-run/v1"
    assert summary["status"] == "completed"
    assert summary["input_sha256"] == hashlib.sha256(b"remote-jpeg-bytes").hexdigest()
    assert transport.commands[0][:2] == ["/usr/local/bin/analyze", "--input"]
    assert transport.commands[0][2].endswith("/input/pic.jpg")
    assert transport.commands[0][3] == "--output-dir"
    assert transport.commands[0][4].endswith("/output")
    by_name = {item["relative_path"]: item for item in summary["outputs"]}
    assert set(by_name) == {"result.json", "extracted.png"}
    assert by_name["extracted.png"]["sha256"] == hashlib.sha256(
        b"\x89PNG\r\n\x1a\npayload"
    ).hexdigest()
    assert summary["result"]["findings"] == [{"kind": "stego"}]
    assert summary["output_skips"] == []
    expected_result_sha = hashlib.sha256(
        b"extracted.png:"
        + by_name["extracted.png"]["sha256"].encode()
        + b"\nresult.json:"
        + by_name["result.json"]["sha256"].encode()
    ).hexdigest()
    assert summary["result_sha256"] == expected_result_sha

    spec = json.loads(
        (Path(summary["job_directory"]) / "request.json").read_text(encoding="utf-8")
    )
    request_sha = hashlib.sha256(
        json.dumps(spec, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    assert summary["request_sha256"] == request_sha

    conn = sqlite3.connect(root / "project.sqlite")
    conn.row_factory = sqlite3.Row
    remote_rows = conn.execute("SELECT * FROM remote_job").fetchall()
    run_rows = conn.execute("SELECT * FROM plugin_run").fetchall()
    outputs = conn.execute("SELECT * FROM plugin_output").fetchall()
    assert len(remote_rows) == 1
    assert remote_rows[0]["request_sha256"] == request_sha
    assert remote_rows[0]["node_name"] == "node-a"
    assert run_rows[0]["status"] == "completed"
    assert len(outputs) == 2
    assert conn.execute("PRAGMA foreign_key_check").fetchall() == []


def test_run_remote_job_failure_timeout_and_missing_result(tmp_path) -> None:
    root = _project_with_artifact(tmp_path / "case-fail")
    manifest = _remote_manifest(tmp_path / "case-fail")
    failing = FakeTransport(tmp_path / "case-fail" / "fake-remote", exit_code=3)
    failed = run_remote_job(
        root, failing, manifest, "artifact-remote", node_name="node-a"
    )
    assert failed["status"] == "failed"
    assert "exited with code 3" in failed["error"]

    root2 = _project_with_artifact(tmp_path / "case-timeout")
    manifest2 = _remote_manifest(tmp_path / "case-timeout")
    timeout = FakeTransport(
        tmp_path / "case-timeout" / "fake-remote", exit_code=0, timed_out=True
    )
    timed = run_remote_job(root2, timeout, manifest2, "artifact-remote", node_name="n")
    assert timed["status"] == "timeout"

    root3 = _project_with_artifact(tmp_path / "case-missing")
    manifest3 = _remote_manifest(tmp_path / "case-missing")
    missing = FakeTransport(tmp_path / "case-missing" / "fake-remote")
    no_result = run_remote_job(root3, missing, manifest3, "artifact-remote", node_name="n")
    assert no_result["status"] == "failed"
    assert "was not produced" in no_result["error"]
    reasons = {item["reason"] for item in no_result["output_skips"]}
    assert "unreadable" in reasons


def test_run_remote_job_rejects_unsafe_manifests(tmp_path) -> None:
    root = _project_with_artifact(tmp_path / "unsafe")
    bad_exec = _remote_manifest(
        tmp_path / "unsafe", executable="relative/tool"
    )
    transport = FakeTransport(tmp_path / "unsafe" / "fake-remote")
    with pytest.raises(ValueError, match="absolute"):
        run_remote_job(root, transport, bad_exec, "artifact-remote", node_name="n")

    bad_arg = _remote_manifest(
        tmp_path / "unsafe", arguments=["--input {input}; rm -rf /", "{output_dir}"]
    )
    with pytest.raises(ValueError, match="shell-safe"):
        run_remote_job(root, transport, bad_arg, "artifact-remote", node_name="n")
    assert load_plugin_manifest(bad_exec)  # locally valid, remotely rejected
