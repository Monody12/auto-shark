"""Constrained SSH/SFTP remote analysis jobs with hash verification."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .core.hashing import hash_file
from .core.ids import stable_id
from .engines.process import ProcessResult, run_bounded
from .plugins import (
    MAX_RESULT_JSON_BYTES,
    _now,
    _safe_input_name,
    load_plugin_manifest,
    verified_artifact,
)
from .project import inspect_project
from .storage import Database

PROBE_SCHEMA = "auto-shark.remote-probe/v1"
RUN_SCHEMA = "auto-shark.remote-run/v1"
JOB_SPEC_SCHEMA = "auto-shark.remote-job/v1"
DEFAULT_REMOTE_ROOT = ".auto-shark-jobs"

REMOTE_TOKEN = re.compile(r"^[A-Za-z0-9_.:@/=+,-]+$")
REMOTE_ABSOLUTE = re.compile(r"^/[A-Za-z0-9_.:@/=+,-]+$")
HOST_TOKEN = re.compile(r"^[A-Za-z0-9_.:@-]+$")


class RemoteTransportError(RuntimeError):
    """A constrained remote transfer or command failed."""


def find_ssh_tools(
    explicit_ssh: Optional[Path] = None, explicit_sftp: Optional[Path] = None
) -> tuple[Optional[Path], Optional[Path]]:
    """Capability-detect ssh/sftp client executables without executing them."""
    candidates = ["ssh", "sftp"]
    found: dict[str, Optional[Path]] = {}
    explicit = {"ssh": explicit_ssh, "sftp": explicit_sftp}
    for name in candidates:
        path = explicit[name]
        if path is None:
            path = Path(shutil.which(name) or "")
            if not str(path):
                windows = Path(
                    r"C:\Windows\System32\OpenSSH"
                ) / f"{name}.exe"
                path = windows if windows.is_file() else None
        found[name] = path if path is not None and Path(path).is_file() else None
    return found["ssh"], found["sftp"]


@dataclass(frozen=True)
class RemoteNodeConfig:
    host: str
    ssh_executable: Path
    sftp_executable: Path
    connect_timeout_seconds: int = 15
    strict_host_key_checking: str = "accept-new"
    remote_root: str = DEFAULT_REMOTE_ROOT

    def validate(self) -> None:
        if not HOST_TOKEN.fullmatch(self.host):
            raise ValueError("remote host must be a plain user@host token")
        if not 1 <= self.connect_timeout_seconds <= 300:
            raise ValueError("connect timeout must be between 1 and 300 seconds")
        if self.strict_host_key_checking not in ("yes", "accept-new", "no"):
            raise ValueError("unsupported StrictHostKeyChecking mode")
        if not REMOTE_TOKEN.fullmatch(self.remote_root) or ".." in self.remote_root:
            raise ValueError("remote root must be a shell-safe path without ..")


class RemoteTransport:
    """Minimal constrained transport interface for remote jobs."""

    def make_directory(self, remote_path: str) -> None:
        raise NotImplementedError

    def put_file(self, local_path: Path, remote_path: str) -> None:
        raise NotImplementedError

    def get_file(self, remote_path: str, local_path: Path) -> None:
        raise NotImplementedError

    def run(
        self,
        command: Sequence[str],
        timeout_seconds: float,
        stdout_limit: int,
        stderr_limit: int,
    ) -> ProcessResult:
        raise NotImplementedError


def _checked_remote_path(remote_path: str) -> str:
    if not REMOTE_TOKEN.fullmatch(remote_path) or ".." in remote_path:
        raise ValueError(f"unsafe remote path rejected: {remote_path!r}")
    return remote_path


class SshTransport(RemoteTransport):
    """ssh/sftp argument-list transport; every remote token is charset-checked."""

    def __init__(self, config: RemoteNodeConfig) -> None:
        config.validate()
        if not config.ssh_executable.is_file() or not config.sftp_executable.is_file():
            raise FileNotFoundError("ssh and sftp client executables are required")
        self.config = config

    def _options(self) -> list[str]:
        return [
            "-o",
            "BatchMode=yes",
            "-o",
            f"ConnectTimeout={self.config.connect_timeout_seconds}",
            "-o",
            f"StrictHostKeyChecking={self.config.strict_host_key_checking}",
        ]

    def ssh_argv(self, command: Sequence[str]) -> list[str]:
        checked = [_checked_remote_path(str(item)) for item in command]
        return [
            str(self.config.ssh_executable),
            *self._options(),
            self.config.host,
            *checked,
        ]

    def run(
        self,
        command: Sequence[str],
        timeout_seconds: float,
        stdout_limit: int,
        stderr_limit: int,
    ) -> ProcessResult:
        return run_bounded(
            self.ssh_argv(command),
            timeout_seconds=timeout_seconds,
            stdout_limit=stdout_limit,
            stderr_limit=stderr_limit,
        )

    def make_directory(self, remote_path: str) -> None:
        result = self.run(["mkdir", "-p", _checked_remote_path(remote_path)], 60, 4096, 4096)
        if result.returncode != 0 or result.timed_out:
            raise RemoteTransportError(
                f"remote mkdir failed with exit code {result.returncode}"
            )

    @staticmethod
    def sftp_batch_text(operations: Sequence[tuple[str, str, str]]) -> str:
        lines = []
        for operation, source, target in operations:
            _checked_remote_path(target)
            if operation == "get":
                _checked_remote_path(source)
            if operation == "put":
                _checked_remote_path(target)
            lines.append(f'{operation} "{Path(source).as_posix()}" "{target}"')
        return "\n".join(lines) + "\n"

    def _transfer(self, operations: Sequence[tuple[str, str, str]], batch_path: Path) -> None:
        batch_path.write_text(self.sftp_batch_text(operations), encoding="utf-8")
        argv = [
            str(self.config.sftp_executable),
            *self._options(),
            "-b",
            str(batch_path),
            self.config.host,
        ]
        result = run_bounded(argv, timeout_seconds=300, stdout_limit=65536, stderr_limit=65536)
        if result.returncode != 0 or result.timed_out:
            raise RemoteTransportError(
                f"sftp transfer failed with exit code {result.returncode}"
            )

    def put_file(self, local_path: Path, remote_path: str) -> None:
        self._transfer([("put", str(local_path), _checked_remote_path(remote_path))],
                       local_path.parent / "sftp-put.bat")

    def get_file(self, remote_path: str, local_path: Path) -> None:
        self._transfer([("get", _checked_remote_path(remote_path), str(local_path))],
                       local_path.parent / "sftp-get.bat")


def probe_remote_node(
    config: RemoteNodeConfig, absolute_paths: Sequence[str]
) -> dict:
    transport = SshTransport(config)
    probes = []
    for path in absolute_paths:
        if not REMOTE_ABSOLUTE.fullmatch(path):
            probes.append({"path": path, "available": False, "reason": "not-absolute"})
            continue
        result = transport.run(["test", "-x", path], 60, 4096, 4096)
        available = result.returncode == 0 and not result.timed_out
        probes.append(
            {
                "path": path,
                "available": available,
                "reason": None if available else "not-executable-or-unreachable",
            }
        )
    return {
        "schema_version": PROBE_SCHEMA,
        "host": config.host,
        "remote_root": config.remote_root,
        "probes": probes,
        "available": all(item["available"] for item in probes),
    }


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def run_remote_job(
    project_path: Path,
    transport: RemoteTransport,
    manifest_path: Path,
    artifact_id: str,
    *,
    node_name: str,
    remote_root: str = DEFAULT_REMOTE_ROOT,
) -> dict:
    manifest = load_plugin_manifest(manifest_path)
    executable = manifest.executable_text
    if not REMOTE_ABSOLUTE.fullmatch(executable):
        raise ValueError("remote manifest executable must be an absolute shell-safe path")
    project = inspect_project(project_path)
    database = Database(project.root / "project.sqlite")
    database.initialize()
    artifact, blob_path, blob_sha256, blob_bytes = verified_artifact(
        project, database, artifact_id
    )

    started_at = _now()
    job_id = stable_id(
        "remote-job/v1",
        {
            "manifest_id": manifest.manifest_id(),
            "artifact_id": artifact_id,
            "input_sha256": blob_sha256,
            "node_name": node_name,
            "started_at": started_at,
        },
    )
    job_dir = project.root / "jobs" / "remote" / job_id
    input_dir = job_dir / "input"
    output_dir = job_dir / "output"
    input_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)
    input_name = _safe_input_name(artifact_id, artifact["suggested_name"])
    input_path = input_dir / input_name
    shutil.copyfile(blob_path, input_path)

    remote_dir = f"{remote_root}/{job_id}"
    remote_input = f"{remote_dir}/input/{input_name}"
    remote_output_dir = f"{remote_dir}/output"
    command = [
        token.replace("{input}", remote_input).replace("{output_dir}", remote_output_dir)
        for token in manifest.arguments
    ]
    command = [executable, *command]
    for token in command:
        if not REMOTE_TOKEN.fullmatch(token):
            raise ValueError(f"remote command token is not shell-safe: {token!r}")

    spec = {
        "schema_version": JOB_SPEC_SCHEMA,
        "job_id": job_id,
        "manifest_id": manifest.manifest_id(),
        "command": command,
        "input": {"name": input_name, "sha256": blob_sha256, "byte_length": blob_bytes},
        "result_file": manifest.result_file,
        "node_name": node_name,
        "remote_dir": remote_dir,
    }
    request_bytes = _canonical_json(spec)
    request_sha256 = hashlib.sha256(request_bytes).hexdigest()
    (job_dir / "request.json").write_bytes(request_bytes + b"\n")

    transport.make_directory(f"{remote_dir}/input")
    transport.make_directory(remote_output_dir)
    transport.put_file(input_path, remote_input)
    result = transport.run(
        command,
        timeout_seconds=float(manifest.timeout_seconds),
        stdout_limit=manifest.stdout_limit_bytes,
        stderr_limit=manifest.stderr_limit_bytes,
    )

    outputs: list[dict[str, object]] = []
    skips: list[dict[str, object]] = []
    result_json: Optional[str] = None
    total_bytes = 0
    result_name = manifest.result_file

    def fetch(relative: str) -> Optional[dict[str, object]]:
        nonlocal total_bytes
        try:
            transport.get_file(f"{remote_output_dir}/{relative}", output_dir / relative)
            file_sha256, file_bytes = hash_file(output_dir / relative)
        except (RemoteTransportError, OSError):
            skips.append({"relative_path": relative, "reason": "unreadable"})
            return None
        if file_bytes > manifest.max_output_file_bytes:
            skips.append({"relative_path": relative, "reason": "file-byte-limit"})
            return None
        if total_bytes + file_bytes > manifest.max_output_total_bytes:
            skips.append({"relative_path": relative, "reason": "total-byte-limit"})
            return None
        total_bytes += file_bytes
        record = {
            "relative_path": relative,
            "byte_length": file_bytes,
            "sha256": file_sha256,
        }
        outputs.append(record)
        return record

    result_record = fetch(result_name) if result_name is not None else None
    if result_record is not None:
        if int(result_record["byte_length"]) > MAX_RESULT_JSON_BYTES:  # type: ignore[arg-type]
            outputs.remove(result_record)
            skips.append({"relative_path": result_name, "reason": "result-too-large"})
        else:
            try:
                parsed = json.loads((output_dir / result_name).read_text(encoding="utf-8"))
                result_json = json.dumps(parsed, ensure_ascii=False, sort_keys=True)
                extra = parsed.get("output_files") if isinstance(parsed, dict) else None
                if isinstance(extra, list):
                    for name in extra[: manifest.max_output_files]:
                        if not isinstance(name, str) or Path(name).name != name:
                            skips.append({"relative_path": str(name), "reason": "unreadable"})
                            continue
                        fetch(name)
            except (OSError, json.JSONDecodeError):
                outputs.remove(result_record)
                skips.append({"relative_path": result_name, "reason": "result-invalid-json"})

    if result.timed_out:
        status = "timeout"
        error: Optional[str] = "remote analyzer exceeded the declared timeout"
    elif result.returncode != 0:
        status = "failed"
        error = f"remote analyzer exited with code {result.returncode}"
    elif result_record is None:
        status = "failed"
        error = "declared remote result file was not produced"
    else:
        status = "completed"
        error = None
    result_sha256 = hashlib.sha256(
        "\n".join(
            f"{item['relative_path']}:{item['sha256']}" for item in sorted(
                outputs, key=lambda item: str(item["relative_path"])
            )
        ).encode("utf-8")
    ).hexdigest()
    ended_at = _now()

    with database.connect() as connection:
        cursor = connection.execute(
            "INSERT INTO plugin_run"
            "(run_id,plugin_id,plugin_version,input_artifact_id,job_directory,status,"
            "result_schema,started_at,ended_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (
                job_id,
                manifest.manifest_id(),
                manifest.version,
                int(artifact["id"]),
                str(job_dir),
                status,
                RUN_SCHEMA,
                started_at,
                ended_at,
            ),
        )
        run_row = int(cursor.lastrowid)
        connection.execute(
            "INSERT INTO plugin_run_detail"
            "(plugin_run_id,exit_code,stdout_bytes,stdout_sha256,stdout_truncated,"
            "stderr_bytes,stderr_sha256,stderr_truncated,argv_json,result_json,error) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                run_row,
                result.returncode,
                len(result.stdout),
                hashlib.sha256(result.stdout).hexdigest(),
                1 if result.stdout_truncated else 0,
                len(result.stderr),
                hashlib.sha256(result.stderr).hexdigest(),
                1 if result.stderr_truncated else 0,
                json.dumps(result.argv),
                result_json,
                error,
            ),
        )
        for output in outputs:
            connection.execute(
                "INSERT OR IGNORE INTO plugin_output"
                "(plugin_run_id,relative_path,byte_length,sha256) VALUES(?,?,?,?)",
                (run_row, output["relative_path"], output["byte_length"], output["sha256"]),
            )
        for skip in skips:
            connection.execute(
                "INSERT OR IGNORE INTO plugin_output_skip"
                "(plugin_run_id,relative_path,reason) VALUES(?,?,?)",
                (run_row, skip["relative_path"], skip["reason"]),
            )
        connection.execute(
            "INSERT INTO remote_job"
            "(job_id,plugin_run_id,node_name,request_sha256,result_sha256,status,"
            "started_at,ended_at) VALUES(?,?,?,?,?,?,?,?)",
            (
                job_id,
                run_row,
                node_name,
                request_sha256,
                result_sha256,
                status,
                started_at,
                ended_at,
            ),
        )

    return {
        "schema_version": RUN_SCHEMA,
        "job_id": job_id,
        "node_name": node_name,
        "manifest_id": manifest.manifest_id(),
        "artifact_id": artifact_id,
        "input_sha256": blob_sha256,
        "input_bytes": blob_bytes,
        "status": status,
        "exit_code": result.returncode,
        "timed_out": result.timed_out,
        "request_sha256": request_sha256,
        "result_sha256": result_sha256,
        "outputs": outputs,
        "output_skips": skips,
        "result": json.loads(result_json) if result_json is not None else None,
        "job_directory": str(job_dir),
        "error": error,
    }
