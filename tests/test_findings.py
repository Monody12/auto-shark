from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from auto_shark.core.ids import EvidenceLocator, evidence_id
from auto_shark.engines.stream import StreamProcessResult
from auto_shark.engines.tshark import TsharkCapabilities
from auto_shark.findings import index_multipart_findings
from auto_shark.project import create_project
from auto_shark.storage import BlobStore, Database


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _capabilities() -> TsharkCapabilities:
    return TsharkCapabilities(
        executable="tshark",
        version_line="TShark 4.6.7",
        fields=(
            "frame.number",
            "mime_multipart.header.content-disposition",
            "mime_multipart.header.content-type",
        ),
        protocols=("mime_multipart",),
        export_objects=(),
        features={"multipart": True},
        missing_core_fields=(),
        usable=True,
        errors=(),
    )


def _project(tmp_path: Path) -> tuple[Path, str]:
    capture = tmp_path / "capture.pcap"
    capture.write_bytes(b"pcap")
    root = tmp_path / "case.auto-shark"
    info = create_project(capture, root, allow_synced=True)
    return root, info.capture_sha256


def _install(monkeypatch, rows: list[bytes]) -> None:
    monkeypatch.setattr("auto_shark.findings.probe_tshark", lambda _: _capabilities())

    def run(argv, consume, **kwargs):
        for row in rows:
            consume(row)
        return StreamProcessResult(tuple(argv), 0, len(rows), b"", False, False, False)

    monkeypatch.setattr("auto_shark.findings.run_streaming_lines", run)


def _http_body(
    root: Path,
    capture_sha256: str,
    *,
    frame: int,
    kind: str,
    response_code: Optional[int],
    body: bytes,
    body_status: str = "complete",
) -> tuple[int, int]:
    database = Database(root / "project.sqlite")
    blob = BlobStore(root / "blobs").put_bytes(body)
    message_public = f"message-{frame}"
    locator = EvidenceLocator(
        capture_sha256=capture_sha256,
        source_kind="http-body",
        frame_start=frame,
        frame_end=frame,
        protocol_message=message_public,
        byte_length=len(body),
    )
    with database.connect() as connection:
        capture_id = int(connection.execute("SELECT id FROM capture").fetchone()[0])
        connection.execute(
            "INSERT INTO frame(capture_id,frame_number) VALUES(?,?)", (capture_id, frame)
        )
        connection.execute(
            "INSERT INTO protocol_message "
            "(message_id,capture_id,representative_frame,protocol,message_kind,fields_json) "
            "VALUES(?,?,?,'http',?,'{}')",
            (message_public, capture_id, frame, kind),
        )
        message_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
        connection.execute(
            "INSERT INTO http_message(protocol_message_id,response_code,content_type) "
            "VALUES(?,?,'multipart/form-data')",
            (message_id, response_code),
        )
        connection.execute(
            "INSERT INTO tool_run(run_id,tool_name,argv_json,started_at,status) "
            "VALUES(?,?,?,?,?)",
            (f"body-{frame}", "test", "[]", _now(), "completed"),
        )
        body_tool_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
        connection.execute(
            "INSERT INTO blob(sha256,byte_length,relative_path,complete,created_at) "
            "VALUES(?,?,?,?,?)",
            (blob.sha256, len(body), blob.path.relative_to(root).as_posix(), 1, _now()),
        )
        blob_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
        connection.execute(
            "INSERT INTO evidence "
            "(evidence_id,capture_id,source_kind,frame_start,frame_end,"
            "protocol_message_id,byte_offset,byte_length,blob_id,locator_json) "
            "VALUES(?,?,'http-body',?,?,?,?,?,?,?)",
            (
                evidence_id(locator),
                capture_id,
                frame,
                frame,
                message_id,
                0,
                len(body),
                blob_id,
                "{}",
            ),
        )
        evidence_db_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
        connection.execute(
            "INSERT INTO http_body "
            "(protocol_message_id,evidence_id,tool_run_id,extracted_length,status,"
            "truncated,updated_at) VALUES(?,?,?,?,?,?,?)",
            (
                message_id,
                evidence_db_id,
                body_tool_id,
                len(body),
                body_status,
                int(body_status != "complete"),
                _now(),
            ),
        )
    return message_id, evidence_db_id


def _artifact(root: Path, message_id: int, parent_evidence_id: int, media_type: str) -> None:
    database = Database(root / "project.sqlite")
    artifact_blob = BlobStore(root / "blobs").put_bytes(b"artifact")
    with database.connect() as connection:
        capture_id = int(connection.execute("SELECT id FROM capture").fetchone()[0])
        connection.execute(
            "INSERT INTO blob(sha256,byte_length,relative_path,media_type,complete,created_at) "
            "VALUES(?,?,?,?,1,?)",
            (
                artifact_blob.sha256,
                artifact_blob.byte_length,
                artifact_blob.path.relative_to(root).as_posix(),
                media_type,
                _now(),
            ),
        )
        blob_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
        source_public = f"carve-{message_id}"
        connection.execute(
            "INSERT INTO evidence "
            "(evidence_id,capture_id,source_kind,protocol_message_id,byte_offset,"
            "byte_length,blob_id,locator_json) VALUES(?,?,'file-carve',?,0,8,?,'{}')",
            (source_public, capture_id, message_id, blob_id),
        )
        source_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
        connection.execute(
            "INSERT INTO artifact "
            "(artifact_id,blob_id,source_evidence_id,detected_media_type,"
            "review_state,created_at) VALUES(?,?,?,?,?,?)",
            (f"artifact-{message_id}", blob_id, source_id, media_type, "unreviewed", _now()),
        )
        artifact_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
        connection.execute(
            "INSERT INTO file_carve "
            "(carve_id,parent_evidence_id,carved_evidence_id,artifact_id,format,"
            "start_offset,byte_length,structural_status,validation_detail,created_at) "
            "VALUES(?,?,?,?,?,0,8,'validated','ok',?)",
            (
                f"file-carve-{message_id}",
                parent_evidence_id,
                source_id,
                artifact_id,
                "test",
                _now(),
            ),
        )


def test_multipart_unique_match_and_http_contradiction_are_idempotent(
    tmp_path, monkeypatch
) -> None:
    root, digest = _project(tmp_path)
    request_id, request_evidence = _http_body(
        root,
        digest,
        frame=233,
        kind="request",
        response_code=None,
        body=b"request",
    )
    _artifact(root, request_id, request_evidence, "image/png")
    _http_body(
        root,
        digest,
        frame=260,
        kind="response",
        response_code=500,
        body=b"prefix upload success suffix",
    )
    rows = [b'233\t"form-data;name=""upfile"";filename=""flag.jpg"""\t"image/jpeg"']
    _install(monkeypatch, rows)
    first = index_multipart_findings(root, Path("tshark"))
    second = index_multipart_findings(root, Path("tshark"))
    assert first.multipart_resolved == second.multipart_resolved == 1
    assert first.type_mismatch_findings == 1
    assert second.type_mismatch_findings == 0
    assert first.contradiction_findings == 1
    assert second.contradiction_findings == 0
    database = Database(root / "project.sqlite")
    with database.connect() as connection:
        assert connection.execute("SELECT count(*) FROM multipart_part").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM finding").fetchone()[0] == 2
        evidence = connection.execute(
            "SELECT frame_start,byte_offset,byte_length,text_value FROM evidence "
            "WHERE source_kind='http-result-semantic'"
        ).fetchone()
        assert tuple(evidence) == (260, 7, 14, "upload success")
        role = connection.execute(
            "SELECT role FROM multipart_part_artifact"
        ).fetchone()[0]
    assert role == "type-mismatch"


def test_multipart_multiple_parts_are_unresolved_and_partial_body_is_not_scanned(
    tmp_path, monkeypatch
) -> None:
    root, digest = _project(tmp_path)
    request_id, request_evidence = _http_body(
        root,
        digest,
        frame=5,
        kind="request",
        response_code=None,
        body=b"request",
    )
    _artifact(root, request_id, request_evidence, "image/png")
    _http_body(
        root,
        digest,
        frame=6,
        kind="response",
        response_code=500,
        body=b"upload success",
        body_status="partial",
    )
    rows = [
        b'5\t"form-data;name=""a""|form-data;name=""b"""\t"text/plain|image/png"'
    ]
    _install(monkeypatch, rows)
    summary = index_multipart_findings(root, Path("tshark"))
    assert summary.multipart_parts == 2
    assert summary.multipart_unresolved == 2
    assert summary.body_scans_skipped == 1
    assert summary.contradiction_findings == 0
