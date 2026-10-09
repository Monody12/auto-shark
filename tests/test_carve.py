import io
import zipfile
from datetime import datetime, timezone

from auto_shark.core.ids import EvidenceLocator, evidence_id
from auto_shark.files.carve import carve_project
from auto_shark.project import create_project
from auto_shark.storage import BlobStore, Database


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _add_body(project, info, frame, body):
    database = Database(project / "project.sqlite")
    blob = BlobStore(project / "blobs").put_bytes(body)
    locator = EvidenceLocator(
        capture_sha256=info.capture_sha256,
        source_kind="http-body",
        frame_start=frame,
        frame_end=frame,
        protocol_message=f"message-{frame}",
        byte_offset=0,
        byte_length=len(body),
    )
    with database.connect() as connection:
        capture_id = int(connection.execute("SELECT id FROM capture").fetchone()[0])
        connection.execute(
            "INSERT INTO frame (capture_id,frame_number) VALUES (?,?)", (capture_id, frame)
        )
        connection.execute(
            "INSERT INTO protocol_message "
            "(message_id,capture_id,representative_frame,protocol,message_kind,fields_json) "
            "VALUES (?,?,?,'http','response','{}')",
            (f"message-{frame}", capture_id, frame),
        )
        message_id = int(
            connection.execute(
                "SELECT id FROM protocol_message WHERE message_id=?", (f"message-{frame}",)
            ).fetchone()[0]
        )
        connection.execute(
            "INSERT INTO blob (sha256,byte_length,relative_path,complete,created_at) "
            "VALUES (?,?,?,?,?) ON CONFLICT(sha256) DO NOTHING",
            (blob.sha256, len(body), blob.path.relative_to(project).as_posix(), 1, _now()),
        )
        blob_id = int(
            connection.execute("SELECT id FROM blob WHERE sha256=?", (blob.sha256,)).fetchone()[0]
        )
        connection.execute(
            "INSERT INTO evidence "
            "(evidence_id,capture_id,source_kind,frame_start,frame_end,protocol_message_id,"
            "byte_offset,byte_length,blob_id,locator_json) "
            "VALUES (?,?,'http-body',?,?,?,?,?,?,?)",
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


def test_carve_is_idempotent_and_preserves_duplicate_sources(tmp_path) -> None:
    capture = tmp_path / "sample.pcap"
    capture.write_bytes(b"capture")
    project = tmp_path / "sample.auto-shark"
    info = create_project(capture, project)
    jpeg = b"\xff\xd8\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00data\xff\xd9"
    body = b"pre" + jpeg + b"tail"
    _add_body(project, info, 1, body)
    _add_body(project, info, 2, body)

    first = carve_project(project, window_bytes=4)
    second = carve_project(project, window_bytes=4)
    assert first.carved_files == second.carved_files == 2
    assert first.unique_artifacts == second.unique_artifacts == 1
    assert first.new_artifacts == 1
    assert second.new_artifacts == 0
    assert first.prefix_regions == first.trailing_regions == 2

    database = Database(project / "project.sqlite")
    with database.connect() as connection:
        assert connection.execute("SELECT count(*) FROM file_scan").fetchone()[0] == 2
        assert connection.execute("SELECT count(*) FROM file_carve").fetchone()[0] == 2
        assert connection.execute("SELECT count(*) FROM artifact").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM artifact_evidence").fetchone()[0] == 2
        ranges = connection.execute(
            "SELECT source_kind,byte_offset,byte_length FROM evidence "
            "WHERE source_kind IN ('file-prefix','file-carve','trailing-data') "
            "ORDER BY frame_start,source_kind"
        ).fetchall()
        assert len(ranges) == 6
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_carve_indexes_nested_archives_in_non_pcap_container(tmp_path) -> None:
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("inner.txt", "secret")
    payload = b"ID3\x03\x00\x00\x00\x00\x00\x00" + b"\x00" * 64 + archive.getvalue()
    capture = tmp_path / "song.mp3"
    capture.write_bytes(payload)
    project = tmp_path / "song.auto-shark"
    create_project(capture, project)

    summary = carve_project(project)
    assert "zip" in summary.formats
    assert summary.carved_files >= 1
    database = Database(project / "project.sqlite")
    with database.connect() as connection:
        finding = connection.execute(
            "SELECT title FROM finding WHERE detector='nested-container'"
        ).fetchone()
        assert finding is not None
        assert "nested" in finding[0].lower()
        kinds = [
            row[0]
            for row in connection.execute("SELECT source_kind FROM evidence")
        ]
        assert "capture-bytes" in kinds
