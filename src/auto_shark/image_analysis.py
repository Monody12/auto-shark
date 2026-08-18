"""Automatic image-artifact analysis through declared analyzer manifests."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .core.ids import stable_id
from .plugins import load_plugin_manifest, run_plugin
from .project import inspect_project
from .remote import DEFAULT_REMOTE_ROOT, RemoteNodeConfig, SshTransport, run_remote_job
from .storage import Database

IMAGE_MEDIA_TYPES = ("image/jpeg", "image/png")
MAX_IMAGE_ARTIFACTS = 32
SUMMARY_SCHEMA = "auto-shark.image-analysis/v1"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class ImageAnalysisSummary:
    payload: dict

    def to_json(self) -> str:
        return json.dumps(self.payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n"


def _record_finding(
    connection, capture_id: int, artifact_row, manifest, summary: dict
) -> Optional[str]:
    """One explainable finding per completed analyzer run; returns its id."""
    finding_id = stable_id(
        "image-analysis-finding/v1",
        {
            "run_id": summary.get("run_id") or summary.get("job_id"),
            "artifact_id": summary["artifact_id"],
        },
    )
    existing = connection.execute(
        "SELECT id FROM finding WHERE finding_id=?", (finding_id,)
    ).fetchone()
    if existing is not None:
        return finding_id
    outputs = ", ".join(
        f"{item['relative_path']} ({item['byte_length']}B sha {item['sha256'][:12]}…)"
        for item in summary.get("outputs", [])
    ) or "no output files"
    connection.execute(
        "INSERT INTO finding"
        "(finding_id,detector,detector_version,title,description,severity,confidence,"
        "recommended_action,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
        (
            finding_id,
            f"image-analyzer:{manifest.name}",
            manifest.version,
            f"{manifest.name} report for {artifact_row['suggested_name'] or 'image artifact'}",
            (
                f"Analyzer exited {summary['exit_code']}. Preserved outputs: {outputs}. "
                f"Job directory: {summary['job_directory']}"
            ),
            "info",
            0.3,
            "Open the preserved stdout.txt/report in the job output directory and "
            "review the analyzer findings for this image.",
            _now(),
        ),
    )
    finding_db = int(
        connection.execute(
            "SELECT id FROM finding WHERE finding_id=?", (finding_id,)
        ).fetchone()[0]
    )
    if artifact_row["source_evidence_id"] is not None:
        connection.execute(
            "INSERT OR IGNORE INTO finding_evidence(finding_id,evidence_id,role) "
            "VALUES(?,?,'subject')",
            (finding_db, int(artifact_row["source_evidence_id"])),
        )
    return finding_id


def analyze_project_images(
    project_path: Path,
    manifest_path: Path,
    *,
    remote_host: Optional[str] = None,
    ssh_executable: Optional[Path] = None,
    sftp_executable: Optional[Path] = None,
    remote_root: str = DEFAULT_REMOTE_ROOT,
    node_name: Optional[str] = None,
    max_artifacts: int = MAX_IMAGE_ARTIFACTS,
) -> ImageAnalysisSummary:
    """Run one declared image analyzer over every eligible image artifact.

    Local mode is the default; pass ``remote_host`` to execute the same
    manifest on the configured Linux node through the constrained runner.
    Completed runs are skipped on rerun (per manifest + artifact).
    """
    if not 0 < max_artifacts <= MAX_IMAGE_ARTIFACTS:
        raise ValueError(f"max_artifacts must be between 1 and {MAX_IMAGE_ARTIFACTS}")
    manifest = load_plugin_manifest(manifest_path)
    project = inspect_project(project_path)
    database = Database(project.root / "project.sqlite")
    database.initialize()
    with database.connect() as connection:
        capture_id = int(
            connection.execute(
                "SELECT id FROM capture WHERE sha256=?", (project.capture_sha256,)
            ).fetchone()[0]
        )
        artifacts = connection.execute(
            "SELECT a.id,a.artifact_id,a.suggested_name,a.detected_media_type,"
            "a.source_evidence_id FROM artifact a JOIN blob b ON b.id=a.blob_id "
            "WHERE a.detected_media_type IN (?,?) AND b.complete=1 "
            "ORDER BY a.created_at,a.artifact_id",
            IMAGE_MEDIA_TYPES,
        ).fetchall()
        already = {
            str(row[0])
            for row in connection.execute(
                "SELECT DISTINCT a.artifact_id FROM plugin_run pr "
                "JOIN artifact a ON a.id=pr.input_artifact_id "
                "WHERE pr.plugin_id=? AND pr.status='completed'",
                (manifest.manifest_id(),),
            )
        }
    results = []
    pending = [artifact for artifact in artifacts if str(artifact["artifact_id"]) not in already]
    skipped = len(artifacts) - len(pending)
    analyzed = 0
    for artifact in pending[:max_artifacts]:
        artifact_id = str(artifact["artifact_id"])
        if remote_host is None:
            summary = run_plugin(project.root, manifest_path, artifact_id)
        else:
            from .remote import find_ssh_tools

            ssh, sftp = find_ssh_tools(ssh_executable, sftp_executable)
            if ssh is None or sftp is None:
                raise FileNotFoundError("ssh and sftp clients are required for remote analysis")
            summary = run_remote_job(
                project.root,
                SshTransport(
                    RemoteNodeConfig(
                        host=remote_host,
                        ssh_executable=ssh,
                        sftp_executable=sftp,
                        remote_root=remote_root,
                    )
                ),
                manifest_path,
                artifact_id,
                node_name=node_name or remote_host,
                remote_root=remote_root,
            )
        analyzed += 1
        results.append(
            {
                "artifact_id": artifact_id,
                "suggested_name": artifact["suggested_name"],
                "media_type": artifact["detected_media_type"],
                "status": summary["status"],
                "run_id": summary.get("run_id") or summary.get("job_id"),
                "outputs": len(summary.get("outputs", [])),
                "skips": len(summary.get("output_skips", [])),
            }
        )
        if summary["status"] == "completed":
            with database.connect() as connection:
                _record_finding(connection, capture_id, artifact, manifest, summary)
    payload = {
        "schema_version": SUMMARY_SCHEMA,
        "manifest_id": manifest.manifest_id(),
        "analyzer": manifest.name,
        "mode": "remote" if remote_host else "local",
        "eligible": len(artifacts),
        "analyzed": analyzed,
        "already_completed": skipped,
        "results": results,
    }
    return ImageAnalysisSummary(payload)
