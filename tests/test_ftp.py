from pathlib import Path

import pytest

from auto_shark.engines.stream import StreamProcessResult
from auto_shark.engines.tshark import TsharkCapabilities
from auto_shark.ftp import _magic, _suggested_name, index_ftp, index_ftp_metadata
from auto_shark.project import create_project
from auto_shark.protocols.ftp import FTP_REQUIRED_FIELDS, selected_ftp_fields
from auto_shark.storage import BlobStore, Database
from auto_shark.tcp import TcpDirectionSummary, TcpReconstructionSummary


def _capabilities() -> TsharkCapabilities:
    fields = set(FTP_REQUIRED_FIELDS) | {"ip.src", "ip.dst"}
    return TsharkCapabilities(
        executable="tshark",
        version_line="TShark test",
        fields=tuple(sorted(fields)),
        protocols=("ftp", "ftp-data", "tcp"),
        export_objects=("ftp-data",),
        features={"ftp": True},
        missing_core_fields=(),
        usable=True,
        errors=(),
    )


def _line(values: dict[str, str], fields: tuple[str, ...]) -> bytes:
    defaults = {
        "frame.time_epoch": "1.0",
        "frame.len": "100",
        "frame.cap_len": "100",
        "tcp.srcport": "21",
        "tcp.dstport": "40000",
        "tcp.len": "10",
        "ip.src": "192.0.2.1",
        "ip.dst": "192.0.2.2",
    }
    defaults.update(values)
    return "\t".join(f'"{defaults.get(field, "")}"' for field in fields).encode()


def _metadata_lines() -> list[bytes]:
    fields = selected_ftp_fields(set(_capabilities().fields))
    return [
        _line(
            {"frame.number": "42", "tcp.stream": "3", "ftp.request.command": "PASV"},
            fields,
        ),
        _line(
            {
                "frame.number": "44",
                "tcp.stream": "3",
                "ftp.response.code": "227",
                "ftp.passive.ip": "192.0.2.1",
                "ftp.passive.port": "14438",
            },
            fields,
        ),
        _line(
            {
                "frame.number": "49",
                "tcp.stream": "3",
                "ftp.request.command": "RETR",
                "ftp.request.arg": "../dir\\flag.rar",
            },
            fields,
        ),
        _line(
            {
                "frame.number": "55",
                "tcp.stream": "4",
                "tcp.srcport": "14438",
                "ftp-data.setup-frame": "44",
                "ftp-data.setup-method": "PASV",
                "ftp-data.command-frame": "49",
                "ftp-data.command": "RETR flag.rar",
            },
            fields,
        ),
        _line(
            {
                "frame.number": "56",
                "tcp.stream": "4",
                "tcp.srcport": "14438",
                "ftp-data.setup-frame": "44",
                "ftp-data.setup-method": "PASV",
                "ftp-data.command-frame": "49",
                "ftp-data.command": "RETR flag.rar",
            },
            fields,
        ),
    ]


def _fake_stream(lines: list[bytes]):
    def run(argv, on_line, **kwargs):
        del kwargs
        for line in lines:
            on_line(line)
        return StreamProcessResult(
            argv=tuple(argv),
            returncode=0,
            line_count=len(lines),
            stderr=b"",
            stderr_truncated=False,
            timed_out=False,
            output_limit_exceeded=False,
        )

    return run


def _project(tmp_path: Path) -> tuple[Path, Database]:
    capture = tmp_path / "capture.pcap"
    capture.write_bytes(b"capture")
    root = tmp_path / "sample.auto-shark"
    create_project(capture, root)
    return root, Database(root / "project.sqlite")


def test_ftp_metadata_groups_data_frames_and_is_idempotent(tmp_path, monkeypatch) -> None:
    root, database = _project(tmp_path)
    monkeypatch.setattr("auto_shark.ftp.run_streaming_lines", _fake_stream(_metadata_lines()))

    first = index_ftp_metadata(root, Path("tshark"), capabilities=_capabilities())
    second = index_ftp_metadata(root, Path("tshark"), capabilities=_capabilities())

    assert first == second
    assert first.messages == 5
    assert first.requests == 2 and first.responses == 1 and first.data_messages == 2
    assert first.transfers == first.indexed_transfers == 1
    with database.connect() as connection:
        assert connection.execute("SELECT count(*) FROM protocol_message").fetchone()[0] == 5
        assert connection.execute("SELECT count(*) FROM ftp_transfer").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM ftp_transfer_message").fetchone()[0] == 2
        transfer = connection.execute(
            "SELECT status,command,argument,suggested_name,data_stream_index FROM ftp_transfer"
        ).fetchone()
        ordinals = [
            int(row[0])
            for row in connection.execute(
                "SELECT ordinal FROM ftp_transfer_message ORDER BY ordinal"
            )
        ]
    assert tuple(transfer) == ("indexed", "RETR", "../dir\\flag.rar", "flag.rar", 4)
    assert ordinals == [0, 1]


def test_ftp_metadata_persists_message_limit_skips(tmp_path, monkeypatch) -> None:
    root, database = _project(tmp_path)
    monkeypatch.setattr("auto_shark.ftp.run_streaming_lines", _fake_stream(_metadata_lines()))

    summary = index_ftp_metadata(root, Path("tshark"), max_messages=1, capabilities=_capabilities())

    assert summary.messages == 1 and summary.skipped_messages == 4
    assert summary.transfers == 0
    with database.connect() as connection:
        assert connection.execute("SELECT count(*) FROM ftp_metadata_skip").fetchone()[0] == 4
        assert connection.execute("SELECT count(*) FROM frame").fetchone()[0] == 5


def test_ftp_metadata_marks_missing_explicit_reference_unresolved(tmp_path, monkeypatch) -> None:
    root, database = _project(tmp_path)
    lines = _metadata_lines()[3:4]
    monkeypatch.setattr("auto_shark.ftp.run_streaming_lines", _fake_stream(lines))

    summary = index_ftp_metadata(root, Path("tshark"), capabilities=_capabilities())

    assert summary.transfers == summary.unresolved_transfers == 1
    with database.connect() as connection:
        transfer = connection.execute(
            "SELECT status,setup_message_id,command_message_id FROM ftp_transfer"
        ).fetchone()
    assert tuple(transfer) == ("unresolved", None, None)


def test_ftp_metadata_keeps_unreferenced_data_frames_separate(tmp_path, monkeypatch) -> None:
    root, database = _project(tmp_path)
    fields = selected_ftp_fields(set(_capabilities().fields))
    lines = [
        _line(
            {
                "frame.number": str(frame),
                "tcp.stream": "4",
                "tcp.srcport": "14438",
                "ftp-data.command": "LIST",
            },
            fields,
        )
        for frame in (55, 56)
    ]
    monkeypatch.setattr("auto_shark.ftp.run_streaming_lines", _fake_stream(lines))

    summary = index_ftp_metadata(root, Path("tshark"), capabilities=_capabilities())

    assert summary.transfers == summary.unresolved_transfers == 2
    with database.connect() as connection:
        assert connection.execute("SELECT count(*) FROM ftp_transfer").fetchone()[0] == 2
        assert connection.execute("SELECT count(*) FROM ftp_transfer_message").fetchone()[0] == 2


def test_ftp_metadata_validates_capabilities_and_limits(tmp_path) -> None:
    root, _ = _project(tmp_path)
    capabilities = _capabilities()
    missing = TsharkCapabilities(
        executable=capabilities.executable,
        version_line=capabilities.version_line,
        fields=tuple(field for field in capabilities.fields if field != "ftp-data.command-frame"),
        protocols=capabilities.protocols,
        export_objects=capabilities.export_objects,
        features={"ftp": False},
        missing_core_fields=(),
        usable=True,
        errors=(),
    )
    with pytest.raises(ValueError, match="command-frame"):
        index_ftp_metadata(root, Path("tshark"), capabilities=missing)
    with pytest.raises(ValueError, match="positive"):
        index_ftp_metadata(root, Path("tshark"), max_transfers=0, capabilities=capabilities)


def test_ftp_suggested_name_removes_paths_and_controls() -> None:
    assert _suggested_name("../dir\\flag.rar") == "flag.rar"
    assert _suggested_name("bad\x00name.rar") == "bad_name.rar"
    assert _suggested_name("../") is None


def test_ftp_magic_recognizes_common_transferred_files(tmp_path) -> None:
    samples = {
        "sample.zip": (b"PK\x03\x04rest", "application/zip", "zip"),
        "sample.png": (b"\x89PNG\r\n\x1a\n", "image/png", "png"),
        "sample.pdf": (b"%PDF-1.7", "application/pdf", "pdf"),
    }
    for name, (content, media_type, description) in samples.items():
        path = tmp_path / name
        path.write_bytes(content)
        assert _magic(path) == (media_type, description)


def _record_reconstruction(root: Path, *, partial_coverage: bool = False) -> None:
    database = Database(root / "project.sqlite")
    payload = b"Rar!\x1a\x07\x00" + b"x" * 13
    blob = BlobStore(root / "blobs").put_bytes(payload)
    with database.connect() as connection:
        capture_id = int(connection.execute("SELECT id FROM capture").fetchone()[0])
        conversation_id = int(
            connection.execute("SELECT id FROM conversation WHERE stream_index=4").fetchone()[0]
        )
        connection.execute(
            "INSERT OR IGNORE INTO blob "
            "(sha256,byte_length,relative_path,complete,created_at) VALUES (?,?,?,1,'now')",
            (blob.sha256, len(payload), blob.path.relative_to(root).as_posix()),
        )
        blob_id = int(
            connection.execute("SELECT id FROM blob WHERE sha256=?", (blob.sha256,)).fetchone()[0]
        )
        connection.execute(
            "INSERT INTO tool_run (run_id,tool_name,argv_json,started_at,status) "
            "VALUES ('tcp-run','test','[]','now','completed')"
        )
        run_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
        for frame, start, length in ((55, 1, 10), (56, 11, 11)):
            connection.execute(
                "INSERT INTO tcp_segment "
                "(segment_id,capture_id,conversation_id,tool_run_id,frame_number,stream_index,"
                "direction,sequence_relative,sequence_raw,payload_length,payload_blob_id,"
                "retransmission,spurious_retransmission,out_of_order,lost_segment) "
                "VALUES (?,?,?,?,?,4,'192.0.2.1:14438>192.0.2.2:40000',?,?,?, ?,0,0,0,0)",
                (
                    f"segment-{frame}",
                    capture_id,
                    conversation_id,
                    run_id,
                    frame,
                    start,
                    start,
                    length,
                    blob_id,
                ),
            )
            segment_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
            connection.execute(
                "INSERT INTO tcp_segment_run (segment_id,tool_run_id) VALUES (?,?)",
                (segment_id, run_id),
            )
        connection.execute(
            "INSERT INTO evidence "
            "(evidence_id,capture_id,source_kind,frame_start,frame_end,direction,byte_offset,"
            "byte_length,blob_id,locator_json) VALUES "
            "('tcp-evidence',?,'tcp-stream',55,56,"
            "'192.0.2.1:14438>192.0.2.2:40000',0,?,?, '{}')",
            (capture_id, len(payload), blob_id),
        )
        evidence_db_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
        connection.execute(
            "INSERT INTO tcp_reconstruction "
            "(reconstruction_id,conversation_id,direction,evidence_id,tool_run_id,status,"
            "sequence_start,sequence_end,unique_bytes,output_bytes,duplicate_bytes,"
            "conflict_bytes,gap_bytes,capture_midstream,max_output_bytes,updated_at) "
            "VALUES ('reconstruction',?,'192.0.2.1:14438>192.0.2.2:40000',?,?,'complete',"
            "1,22,21,21,0,0,0,0,100,'now')",
            (conversation_id, evidence_db_id, run_id),
        )
        reconstruction_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
        segment_ids = {
            int(row["frame_number"]): int(row["id"])
            for row in connection.execute("SELECT id,frame_number FROM tcp_segment")
        }
        connection.execute(
            "INSERT INTO tcp_reconstruction_source "
            "(reconstruction_id,segment_id,sequence_offset,output_offset,byte_length,role) "
            "VALUES (?,?,?,?,?,'primary')",
            (reconstruction_id, segment_ids[55], 1, 0, 10),
        )
        if not partial_coverage:
            connection.execute(
                "INSERT INTO tcp_reconstruction_source "
                "(reconstruction_id,segment_id,sequence_offset,output_offset,byte_length,role) "
                "VALUES (?,?,?,?,?,'primary')",
                (reconstruction_id, segment_ids[56], 11, 10, 11),
            )


def _fake_reconstruct(root: Path):
    def reconstruct(project, stream, tshark, **kwargs):
        del tshark, kwargs
        assert Path(project) == root and stream == 4
        return TcpReconstructionSummary(
            project=str(root),
            stream_index=4,
            indexed_segments=2,
            indexed_payload_bytes=21,
            skipped_segments=0,
            index_truncated=False,
            directions=(
                TcpDirectionSummary(
                    direction="192.0.2.1:14438>192.0.2.2:40000",
                    status="complete",
                    segments=2,
                    sequence_start=1,
                    sequence_end=22,
                    unique_bytes=21,
                    output_bytes=21,
                    duplicate_bytes=0,
                    conflict_bytes=0,
                    gap_bytes=0,
                    gaps=0,
                    conflicts=0,
                    capture_midstream=False,
                    evidence_id="tcp-evidence",
                    blob_sha256=None,
                ),
            ),
        )

    return reconstruct


def test_index_ftp_persists_complete_static_artifact_idempotently(tmp_path, monkeypatch) -> None:
    root, database = _project(tmp_path)
    monkeypatch.setattr("auto_shark.ftp.run_streaming_lines", _fake_stream(_metadata_lines()))
    index_ftp_metadata(root, Path("tshark"), capabilities=_capabilities())
    _record_reconstruction(root)
    monkeypatch.setattr("auto_shark.ftp.reconstruct_tcp_stream", _fake_reconstruct(root))

    first = index_ftp(root, Path("tshark"), capabilities=_capabilities())
    second = index_ftp(root, Path("tshark"), capabilities=_capabilities())

    assert first == second
    assert first.complete == first.artifacts == 1
    assert first.output_bytes == 21
    with database.connect() as connection:
        counts = {
            table: int(connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0])
            for table in ("ftp_transfer", "evidence", "artifact", "artifact_evidence")
        }
        row = connection.execute(
            "SELECT ft.status,ft.output_bytes,e.source_kind,e.frame_start,e.frame_end,"
            "e.byte_offset,e.byte_length,b.magic_description,a.suggested_name,a.review_state "
            "FROM ftp_transfer ft JOIN evidence e ON e.id=ft.evidence_id "
            "JOIN blob b ON b.id=e.blob_id JOIN artifact a ON a.id=ft.artifact_id"
        ).fetchone()
    assert counts == {"ftp_transfer": 1, "evidence": 2, "artifact": 1, "artifact_evidence": 1}
    assert tuple(row) == (
        "complete",
        21,
        "ftp-data",
        55,
        56,
        0,
        21,
        "rar4",
        "flag.rar",
        "unreviewed",
    )


def test_index_ftp_rejects_partial_frame_coverage(tmp_path, monkeypatch) -> None:
    root, database = _project(tmp_path)
    monkeypatch.setattr("auto_shark.ftp.run_streaming_lines", _fake_stream(_metadata_lines()))
    index_ftp_metadata(root, Path("tshark"), capabilities=_capabilities())
    _record_reconstruction(root, partial_coverage=True)
    monkeypatch.setattr("auto_shark.ftp.reconstruct_tcp_stream", _fake_reconstruct(root))

    summary = index_ftp(root, Path("tshark"), capabilities=_capabilities())

    assert summary.partial == 1 and summary.artifacts == 0
    with database.connect() as connection:
        transfer = connection.execute(
            "SELECT status,evidence_id,artifact_id,error FROM ftp_transfer"
        ).fetchone()
    assert transfer[0] == "partial" and transfer[1] is None and transfer[2] is None
    assert "cover" in transfer[3]


def test_index_ftp_skips_budget_before_reconstruction(tmp_path, monkeypatch) -> None:
    root, database = _project(tmp_path)
    monkeypatch.setattr("auto_shark.ftp.run_streaming_lines", _fake_stream(_metadata_lines()))

    def unexpected(*args, **kwargs):
        raise AssertionError("TCP reconstruction must not run over budget")

    monkeypatch.setattr("auto_shark.ftp.reconstruct_tcp_stream", unexpected)
    summary = index_ftp(root, Path("tshark"), max_transfer_bytes=5, capabilities=_capabilities())

    assert summary.skipped_budget == 1 and summary.output_bytes == 0 and summary.artifacts == 0
    with database.connect() as connection:
        transfer = connection.execute(
            "SELECT status,reconstruction_id,evidence_id,artifact_id FROM ftp_transfer"
        ).fetchone()
    assert tuple(transfer) == ("skipped-budget", None, None, None)


def test_index_ftp_persists_reconstruction_failure(tmp_path, monkeypatch) -> None:
    root, database = _project(tmp_path)
    monkeypatch.setattr("auto_shark.ftp.run_streaming_lines", _fake_stream(_metadata_lines()))

    def fail(*args, **kwargs):
        raise ValueError("synthetic reconstruction failure")

    monkeypatch.setattr("auto_shark.ftp.reconstruct_tcp_stream", fail)
    summary = index_ftp(root, Path("tshark"), capabilities=_capabilities())

    assert summary.failed == 1 and summary.artifacts == 0 and summary.output_bytes == 0
    with database.connect() as connection:
        transfer = connection.execute(
            "SELECT status,reconstruction_id,evidence_id,artifact_id,error FROM ftp_transfer"
        ).fetchone()
    assert tuple(transfer[:4]) == ("failed", None, None, None)
    assert "synthetic reconstruction failure" in transfer[4]
