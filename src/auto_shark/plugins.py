"""Declared external analyzer manifests and bounded isolated runs."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .core.hashing import hash_file
from .core.ids import stable_id
from .engines.process import run_bounded
from .project import inspect_project
from .storage import Database

PLUGIN_SCHEMA = "auto-shark.plugin/v1"
PROBE_SCHEMA = "auto-shark.plugin-probe/v1"
RUN_SCHEMA = "auto-shark.plugin-run/v1"

MAX_TIMEOUT_SECONDS = 3600
MAX_STDOUT_BYTES = 16 * 1024 * 1024
MAX_STDERR_BYTES = 1024 * 1024
MAX_OUTPUT_FILES = 64
MAX_OUTPUT_FILE_BYTES = 64 * 1024 * 1024
MAX_OUTPUT_TOTAL_BYTES = 256 * 1024 * 1024
MAX_RESULT_JSON_BYTES = 1024 * 1024
PLACEHOLDERS = frozenset(("{input}", "{output_dir}"))

_SKIP_REASONS = (
    "file-limit",
    "file-byte-limit",
    "total-byte-limit",
    "unreadable",
    "result-too-large",
    "result-invalid-json",
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class PluginManifest:
    path: Path
    name: str
    version: str
    executable: Path
    executable_text: str
    capabilities: tuple[str, ...]
    arguments: tuple[str, ...]
    timeout_seconds: int
    stdout_limit_bytes: int
    stderr_limit_bytes: int
    max_output_files: int
    max_output_file_bytes: int
    max_output_total_bytes: int
    result_file: Optional[str]

    def limits_json(self) -> str:
        return json.dumps(
            {
                "timeout_seconds": self.timeout_seconds,
                "stdout_limit_bytes": self.stdout_limit_bytes,
                "stderr_limit_bytes": self.stderr_limit_bytes,
                "max_output_files": self.max_output_files,
                "max_output_file_bytes": self.max_output_file_bytes,
                "max_output_total_bytes": self.max_output_total_bytes,
                "result_file": self.result_file,
            },
            ensure_ascii=False,
            sort_keys=True,
        )

    def manifest_id(self) -> str:
        return stable_id(
            "plugin-manifest/v1",
            {
                "name": self.name,
                "version": self.version,
                "executable": str(self.executable),
                "capabilities": list(self.capabilities),
                "arguments": list(self.arguments),
                "limits": json.loads(self.limits_json()),
            },
        )

    def to_json(self) -> str:
        return json.dumps(
            {
                "schema_version": PLUGIN_SCHEMA,
                "manifest_id": self.manifest_id(),
                "path": str(self.path),
                "name": self.name,
                "version": self.version,
                "executable": str(self.executable),
                "capabilities": list(self.capabilities),
                "arguments": list(self.arguments),
                "result_file": self.result_file,
                "limits": json.loads(self.limits_json()),
            },
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
        )


def _bounded(value: object, name: str, maximum: int, minimum: int = 1) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{name} must be an integer")
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def load_plugin_manifest(manifest_path: Path) -> PluginManifest:
    path = Path(manifest_path)
    if not path.is_file():
        raise FileNotFoundError(str(path))
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"manifest is not readable JSON: {error}") from error
    if not isinstance(document, dict):
        raise ValueError("manifest must be a JSON object")
    if document.get("schema_version") != PLUGIN_SCHEMA:
        raise ValueError(f"manifest schema_version must be {PLUGIN_SCHEMA}")
    name = document.get("name")
    version = document.get("version")
    executable = document.get("executable")
    capabilities = document.get("capabilities")
    arguments = document.get("arguments")
    if not isinstance(name, str) or not name.strip():
        raise ValueError("manifest name must be a nonempty string")
    if not isinstance(version, str) or not version.strip():
        raise ValueError("manifest version must be a nonempty string")
    if not isinstance(executable, str) or not executable.strip():
        raise ValueError("manifest executable must be a nonempty path string")
    if (
        not isinstance(capabilities, list)
        or not capabilities
        or not all(isinstance(item, str) and item.strip() for item in capabilities)
    ):
        raise ValueError("manifest capabilities must be a nonempty string list")
    if (
        not isinstance(arguments, list)
        or not arguments
        or not all(isinstance(item, str) and item for item in arguments)
    ):
        raise ValueError("manifest arguments must be a nonempty argument list")
    if not any("{input}" in item for item in arguments):
        raise ValueError("manifest arguments must reference {input}")
    for item in arguments:
        for placeholder in re.findall(r"\{[^}]*\}", item):
            if placeholder not in PLACEHOLDERS:
                raise ValueError(f"unsupported manifest placeholder {placeholder}")
    result_file = document.get("result_file")
    if result_file is not None and (
        not isinstance(result_file, str)
        or not result_file
        or Path(result_file).name != result_file
    ):
        raise ValueError("manifest result_file must be a plain file name")
    timeout = _bounded(document.get("timeout_seconds"), "timeout_seconds", MAX_TIMEOUT_SECONDS)
    stdout_limit = _bounded(
        document.get("stdout_limit_bytes"), "stdout_limit_bytes", MAX_STDOUT_BYTES
    )
    stderr_limit = _bounded(
        document.get("stderr_limit_bytes"), "stderr_limit_bytes", MAX_STDERR_BYTES
    )
    max_files = _bounded(document.get("max_output_files"), "max_output_files", MAX_OUTPUT_FILES)
    max_file_bytes = _bounded(
        document.get("max_output_file_bytes"), "max_output_file_bytes", MAX_OUTPUT_FILE_BYTES
    )
    max_total_bytes = _bounded(
        document.get("max_output_total_bytes"),
        "max_output_total_bytes",
        MAX_OUTPUT_TOTAL_BYTES,
    )
    return PluginManifest(
        path=path,
        name=name.strip(),
        version=version.strip(),
        executable=Path(executable),
        executable_text=executable,
        capabilities=tuple(item.strip() for item in capabilities),
        arguments=tuple(arguments),
        timeout_seconds=timeout,
        stdout_limit_bytes=stdout_limit,
        stderr_limit_bytes=stderr_limit,
        max_output_files=max_files,
        max_output_file_bytes=max_file_bytes,
        max_output_total_bytes=max_total_bytes,
        result_file=result_file,
    )


def probe_plugin(manifest_path: Path) -> dict:
    manifest = load_plugin_manifest(manifest_path)
    executable_found = manifest.executable.is_file()
    return {
        "schema_version": PROBE_SCHEMA,
        "manifest_id": manifest.manifest_id(),
        "name": manifest.name,
        "version": manifest.version,
        "capabilities": list(manifest.capabilities),
        "executable": str(manifest.executable),
        "executable_found": executable_found,
        "available": executable_found,
    }


def _safe_input_name(artifact_id: str, suggested: Optional[str]) -> str:
    if suggested:
        cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", suggested)[:64]
        if cleaned and not cleaned.startswith(".") and cleaned != ".":
            return cleaned
    return re.sub(r"[^A-Za-z0-9._-]", "_", artifact_id) + ".bin"


def verified_artifact(project, database: Database, artifact_id: str):
    """Return (artifact row, blob path, sha256, byte length) after hash checks."""
    with database.connect() as connection:
        artifact = connection.execute(
            "SELECT a.id,a.artifact_id,a.suggested_name,a.blob_id,b.sha256,"
            "b.relative_path,b.byte_length,b.complete "
            "FROM artifact a JOIN blob b ON b.id=a.blob_id WHERE a.artifact_id=?",
            (artifact_id,),
        ).fetchone()
    if artifact is None:
        raise ValueError(f"artifact not found: {artifact_id}")
    if not bool(artifact["complete"]):
        raise ValueError(f"artifact blob is incomplete: {artifact_id}")
    blob_path = (project.root / str(artifact["relative_path"])).resolve()
    try:
        blob_path.relative_to((project.root).resolve())
    except ValueError as error:
        raise ValueError("artifact blob path escapes the project") from error
    if not blob_path.is_file():
        raise FileNotFoundError(f"artifact blob file missing: {blob_path}")
    blob_sha256, blob_bytes = hash_file(blob_path)
    if blob_sha256 != str(artifact["sha256"]) or blob_bytes != int(artifact["byte_length"]):
        raise ValueError("artifact blob failed hash or length verification")
    return artifact, blob_path, blob_sha256, blob_bytes


def _hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run_plugin(project_path: Path, manifest_path: Path, artifact_id: str) -> dict:
    manifest = load_plugin_manifest(manifest_path)
    if not manifest.executable.is_file():
        raise FileNotFoundError(f"plugin executable not found: {manifest.executable}")
    project = inspect_project(project_path)
    database = Database(project.root / "project.sqlite")
    database.initialize()
    artifact, blob_path, blob_sha256, blob_bytes = verified_artifact(
        project, database, artifact_id
    )

    started_at = _now()
    run_id = stable_id(
        "plugin-run/v1",
        {
            "manifest_id": manifest.manifest_id(),
            "artifact_id": artifact_id,
            "input_sha256": blob_sha256,
            "started_at": started_at,
        },
    )
    job_dir = project.root / "jobs" / "plugins" / run_id
    input_dir = job_dir / "input"
    output_dir = job_dir / "output"
    input_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)
    input_path = input_dir / _safe_input_name(artifact_id, artifact["suggested_name"])
    shutil.copyfile(blob_path, input_path)

    argv = [str(manifest.executable)] + [
        argument.replace("{input}", str(input_path)).replace("{output_dir}", str(output_dir))
        for argument in manifest.arguments
    ]
    result = run_bounded(
        argv,
        timeout_seconds=float(manifest.timeout_seconds),
        stdout_limit=manifest.stdout_limit_bytes,
        stderr_limit=manifest.stderr_limit_bytes,
    )

    outputs: list[dict[str, object]] = []
    skips: list[dict[str, object]] = []
    result_json: Optional[str] = None
    total_bytes = 0
    output_files = sorted(
        path for path in output_dir.rglob("*") if path.is_file()
    )
    for ordinal, path in enumerate(output_files):
        relative = path.relative_to(output_dir).as_posix()
        if ordinal >= manifest.max_output_files:
            skips.append({"relative_path": relative, "reason": "file-limit"})
            continue
        try:
            file_sha256, file_bytes = hash_file(path)
        except OSError:
            skips.append({"relative_path": relative, "reason": "unreadable"})
            continue
        if file_bytes > manifest.max_output_file_bytes:
            skips.append({"relative_path": relative, "reason": "file-byte-limit"})
            continue
        if total_bytes + file_bytes > manifest.max_output_total_bytes:
            skips.append({"relative_path": relative, "reason": "total-byte-limit"})
            continue
        total_bytes += file_bytes
        outputs.append(
            {"relative_path": relative, "byte_length": file_bytes, "sha256": file_sha256}
        )
    if manifest.result_file is not None:
        result_path = output_dir / manifest.result_file
        recorded = any(
            output["relative_path"] == manifest.result_file for output in outputs
        )
        if recorded:
            if result_path.stat().st_size > MAX_RESULT_JSON_BYTES:
                outputs = [
                    output
                    for output in outputs
                    if output["relative_path"] != manifest.result_file
                ]
                skips.append(
                    {"relative_path": manifest.result_file, "reason": "result-too-large"}
                )
            else:
                try:
                    parsed = json.loads(result_path.read_text(encoding="utf-8"))
                    result_json = json.dumps(parsed, ensure_ascii=False, sort_keys=True)
                except (OSError, json.JSONDecodeError):
                    outputs = [
                        output
                        for output in outputs
                        if output["relative_path"] != manifest.result_file
                    ]
                    skips.append(
                        {
                            "relative_path": manifest.result_file,
                            "reason": "result-invalid-json",
                        }
                    )
        elif not result_path.is_file():
            skips.append({"relative_path": manifest.result_file, "reason": "unreadable"})

    if result.timed_out:
        status = "timeout"
        error: Optional[str] = "analyzer exceeded the declared timeout"
    elif result.returncode != 0 or result.output_limit_exceeded:
        status = "failed"
        error = (
            "analyzer output exceeded the declared limits"
            if result.output_limit_exceeded
            else f"analyzer exited with code {result.returncode}"
        )
    else:
        status = "completed"
        error = None
    ended_at = _now()

    with database.connect() as connection:
        connection.execute(
            "INSERT INTO plugin_manifest"
            "(manifest_id,name,version,schema_version,manifest_path,executable,"
            "capabilities_json,arguments_json,limits_json,registered_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(name,version) DO UPDATE SET manifest_id=excluded.manifest_id",
            (
                manifest.manifest_id(),
                manifest.name,
                manifest.version,
                PLUGIN_SCHEMA,
                str(manifest.path),
                str(manifest.executable),
                json.dumps(list(manifest.capabilities)),
                json.dumps(list(manifest.arguments)),
                manifest.limits_json(),
                ended_at,
            ),
        )
        cursor = connection.execute(
            "INSERT INTO plugin_run"
            "(run_id,plugin_id,plugin_version,input_artifact_id,job_directory,status,"
            "result_schema,started_at,ended_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (
                run_id,
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
                _hash_bytes(result.stdout),
                1 if result.stdout_truncated else 0,
                len(result.stderr),
                _hash_bytes(result.stderr),
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

    return {
        "schema_version": RUN_SCHEMA,
        "run_id": run_id,
        "manifest_id": manifest.manifest_id(),
        "plugin": manifest.name,
        "plugin_version": manifest.version,
        "artifact_id": artifact_id,
        "input_sha256": blob_sha256,
        "input_bytes": blob_bytes,
        "status": status,
        "exit_code": result.returncode,
        "timed_out": result.timed_out,
        "stdout_bytes": len(result.stdout),
        "stdout_sha256": _hash_bytes(result.stdout),
        "stdout_truncated": result.stdout_truncated,
        "stderr_bytes": len(result.stderr),
        "stderr_sha256": _hash_bytes(result.stderr),
        "stderr_truncated": result.stderr_truncated,
        "outputs": outputs,
        "output_skips": skips,
        "result": json.loads(result_json) if result_json is not None else None,
        "job_directory": str(job_dir),
        "error": error,
    }
