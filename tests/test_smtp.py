import base64
import hashlib
import json
from pathlib import Path

from auto_shark.engines.stream import StreamProcessResult
from auto_shark.engines.tshark import TsharkCapabilities
from auto_shark.project import create_project
from auto_shark.smtp import (
    SMTP_FIELDS,
    SMTP_REQUIRED_FIELDS,
    dot_unescape_with_map,
    extract_smtp_data,
    extract_smtp_messages,
    parse_smtp_line,
    selected_smtp_fields,
)
from auto_shark.storage import Database
from auto_shark.tcp import TcpDirectionSummary, TcpReconstructionSummary


def _project(tmp_path: Path) -> Path:
    capture = tmp_path / "mail.pcap"
    capture.write_bytes(b"pcap")
    root = tmp_path / "mail.auto-shark"
    create_project(capture, root, allow_synced=True)
    database = Database(root / "project.sqlite")
    with database.connect() as connection:
        capture_id = int(connection.execute("SELECT id FROM capture").fetchone()[0])
        connection.execute(
            "INSERT INTO evidence"
            "(evidence_id,capture_id,source_kind,byte_offset,byte_length,locator_json) "
            "VALUES('tcp-parent',?,'tcp-reconstruction',0,1,'{}')",
            (capture_id,),
        )
    return root


def _capabilities() -> TsharkCapabilities:
    fields = set(SMTP_REQUIRED_FIELDS) | {
        "ip.src",
        "ip.dst",
        "frame.time_epoch",
        "tcp.seq",
        "tcp.seq_raw",
        "tcp.len",
        "tcp.payload",
        "tcp.flags.syn",
        "tcp.flags.ack",
        "tcp.flags.fin",
        "tcp.flags.reset",
        "frame.cap_len",
        "frame.len",
    }
    return TsharkCapabilities(
        executable="fake-tshark",
        version_line="TShark test",
        fields=tuple(sorted(fields)),
        protocols=("smtp", "tcp"),
        export_objects=("imf",),
        features={"smtp": True},
        missing_core_fields=(),
        usable=True,
        errors=(),
    )


def _row(fields: tuple[str, ...], **values: str) -> bytes:
    return "\t".join(f'"{values.get(field, "")}"' for field in fields).encode()


def _message(payload: bytes) -> bytes:
    encoded = base64.b64encode(payload)
    return (
        b"From: sender@example.test\r\n"
        b"To: receiver@example.test\r\n"
        b"Subject: bounded attachment\r\n"
        b"MIME-Version: 1.0\r\n"
        b'Content-Type: multipart/mixed; boundary="boundary"\r\n'
        b"\r\n"
        b"--boundary\r\n"
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"hello\r\n"
        b"--boundary\r\n"
        b"Content-Type: image/png\r\n"
        b'Content-Disposition: attachment; filename="pixel.png"\r\n'
        b"Content-Transfer-Encoding: base64\r\n"
        b"\r\n" + encoded + b"\r\n"
        b"--boundary--\r\n"
    )


def test_smtp_row_data_extraction_and_dot_unescape() -> None:
    fields = selected_smtp_fields(set(SMTP_FIELDS) - {"ipv6.src", "ipv6.dst"})
    row = _row(
        fields,
        **{
            "frame.number": "10",
            "tcp.stream": "4",
            "ip.src": "192.0.2.1",
            "ip.dst": "192.0.2.2",
            "tcp.srcport": "12345",
            "tcp.dstport": "25",
            "smtp.req.command": "DATA",
        },
    )
    parsed = parse_smtp_line(row, fields)
    assert parsed["stream"] == 4
    assert parsed["commands"] == ("DATA",)
    assert parsed["direction"] == "192.0.2.1:12345>192.0.2.2:25"

    raw = b"Subject: x\r\n\r\n..hidden\r\n"
    stream = b"EHLO test\r\nDATA\r\n" + raw + b".\r\nQUIT\r\n"
    assert extract_smtp_data(stream, 1) == ((17, raw),)
    unescaped, mapping = dot_unescape_with_map(raw)
    assert unescaped.endswith(b".hidden\r\n")
    assert mapping[unescaped.index(b".hidden")] == raw.index(b"..hidden") + 1


def test_smtp_incomplete_data_is_explicitly_counted_and_located(tmp_path, monkeypatch) -> None:
    root = _project(tmp_path)
    fields = selected_smtp_fields(set(_capabilities().fields))
    line = _row(
        fields,
        **{
            "frame.number": "8",
            "tcp.stream": "2",
            "ip.src": "192.0.2.1",
            "ip.dst": "192.0.2.2",
            "tcp.srcport": "12345",
            "tcp.dstport": "25",
            "smtp.req.command": "MAIL|RCPT|DATA",
        },
    )

    def fake_run(argv, callback, **_limits):
        callback(line)
        return StreamProcessResult(tuple(argv), 0, 1, b"", False, False, False)

    monkeypatch.setattr("auto_shark.smtp.run_streaming_lines", fake_run)
    summary = extract_smtp_messages(root, Path("tshark.exe"), capabilities=_capabilities())

    assert summary.status == "partial"
    assert summary.unmatched_data == 1
    assert summary.messages == ()
    with Database(root / "project.sqlite").connect() as connection:
        skip = connection.execute(
            "SELECT tcp_stream,frame_number,reason,count FROM smtp_skip "
            "WHERE reason='data-not-reassembled'"
        ).fetchone()
    assert tuple(skip) == (2, 8, "data-not-reassembled", 1)


def test_smtp_extract_persists_message_attachment_and_exact_source(tmp_path, monkeypatch) -> None:
    root = _project(tmp_path)
    attachment = b"\x89PNG\r\n\x1a\nsynthetic"
    eml = _message(attachment)
    stream = b"EHLO mail\r\nDATA\r\n" + eml + b".\r\nQUIT\r\n"
    direction = "192.0.2.1:12345>192.0.2.2:25"
    fields = selected_smtp_fields(set(_capabilities().fields))
    lines = [
        _row(
            fields,
            **{
                "frame.number": "10",
                "tcp.stream": "4",
                "ip.src": "192.0.2.1",
                "ip.dst": "192.0.2.2",
                "tcp.srcport": "12345",
                "tcp.dstport": "25",
                "smtp.req.command": "DATA",
            },
        ),
        _row(
            fields,
            **{
                "frame.number": "20",
                "tcp.stream": "4",
                "ip.src": "192.0.2.1",
                "ip.dst": "192.0.2.2",
                "tcp.srcport": "12345",
                "tcp.dstport": "25",
                "smtp.data.reassembled.length": str(len(eml)),
            },
        ),
    ]

    def fake_run(argv, callback, **_limits):
        for line in lines:
            callback(line)
        return StreamProcessResult(tuple(argv), 0, len(lines), b"", False, False, False)

    direction_summary = TcpDirectionSummary(
        direction=direction,
        status="complete",
        segments=2,
        sequence_start=1,
        sequence_end=len(stream) + 1,
        unique_bytes=len(stream),
        output_bytes=len(stream),
        duplicate_bytes=0,
        conflict_bytes=0,
        gap_bytes=0,
        gaps=0,
        conflicts=0,
        capture_midstream=False,
        evidence_id="tcp-parent",
        blob_sha256="a" * 64,
    )
    monkeypatch.setattr("auto_shark.smtp.run_streaming_lines", fake_run)
    monkeypatch.setattr(
        "auto_shark.smtp.reconstruct_tcp_stream",
        lambda *args, **kwargs: TcpReconstructionSummary(
            str(root), 4, 2, len(stream), 0, False, (direction_summary,)
        ),
    )
    monkeypatch.setattr(
        "auto_shark.smtp._reconstruction_blob",
        lambda *_args: (1, stream),
    )
    monkeypatch.setattr("auto_shark.smtp._source_frames", lambda *_args: [11, 12, 20])

    first = extract_smtp_messages(root, Path("tshark.exe"), capabilities=_capabilities())
    second = extract_smtp_messages(root, Path("tshark.exe"), capabilities=_capabilities())

    assert first.status == second.status == "completed"
    message = first.messages[0]
    assert message.status == "complete"
    assert message.sha256 == hashlib.sha256(eml).hexdigest()
    assert message.subject == "bounded attachment"
    recovered = message.attachments[0]
    assert recovered.status == "complete"
    assert recovered.filename == "pixel.png"
    assert recovered.sha256 == hashlib.sha256(attachment).hexdigest()
    assert recovered.source_offset is not None and recovered.source_offset > message.source_offset

    database = Database(root / "project.sqlite")
    with database.connect() as connection:
        counts = {
            table: int(connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0])
            for table in (
                "smtp_message",
                "smtp_attachment",
                "artifact",
                "artifact_evidence",
            )
        }
        locator = json.loads(
            connection.execute(
                "SELECT locator_json FROM evidence WHERE source_kind='smtp-attachment'"
            ).fetchone()[0]
        )
        blob = connection.execute(
            "SELECT b.relative_path FROM smtp_attachment sa "
            "JOIN evidence e ON e.id=sa.evidence_id JOIN blob b ON b.id=e.blob_id"
        ).fetchone()
    assert counts == {
        "smtp_message": 1,
        "smtp_attachment": 1,
        "artifact": 1,
        "artifact_evidence": 1,
    }
    assert locator["contributing_frames"] == [11, 12, 20]
    assert locator["source_stream_range"] == [
        recovered.source_offset,
        recovered.source_offset + recovered.source_length,
    ]
    assert (root / str(blob["relative_path"])).read_bytes() == attachment


def test_smtp_attachment_budget_records_skip_without_artifact(tmp_path, monkeypatch) -> None:
    root = _project(tmp_path)
    attachment = b"large attachment"
    eml = _message(attachment)
    stream = b"DATA\r\n" + eml + b".\r\n"
    direction = "192.0.2.1:12345>192.0.2.2:25"
    fields = selected_smtp_fields(set(_capabilities().fields))
    lines = [
        _row(
            fields,
            **{
                "frame.number": "1",
                "tcp.stream": "0",
                "ip.src": "192.0.2.1",
                "ip.dst": "192.0.2.2",
                "tcp.srcport": "12345",
                "tcp.dstport": "25",
                "smtp.req.command": "DATA",
            },
        ),
        _row(
            fields,
            **{
                "frame.number": "2",
                "tcp.stream": "0",
                "ip.src": "192.0.2.1",
                "ip.dst": "192.0.2.2",
                "tcp.srcport": "12345",
                "tcp.dstport": "25",
                "smtp.data.reassembled.length": str(len(eml)),
            },
        ),
    ]

    def fake_run(argv, callback, **_limits):
        for line in lines:
            callback(line)
        return StreamProcessResult(tuple(argv), 0, len(lines), b"", False, False, False)

    monkeypatch.setattr("auto_shark.smtp.run_streaming_lines", fake_run)
    monkeypatch.setattr(
        "auto_shark.smtp.reconstruct_tcp_stream",
        lambda *args, **kwargs: TcpReconstructionSummary(
            str(root),
            0,
            1,
            len(stream),
            0,
            False,
            (
                TcpDirectionSummary(
                    direction,
                    "complete",
                    1,
                    1,
                    len(stream) + 1,
                    len(stream),
                    len(stream),
                    0,
                    0,
                    0,
                    0,
                    0,
                    False,
                    "tcp-parent",
                    "a" * 64,
                ),
            ),
        ),
    )
    monkeypatch.setattr("auto_shark.smtp._reconstruction_blob", lambda *_args: (1, stream))
    monkeypatch.setattr("auto_shark.smtp._source_frames", lambda *_args: [1, 2])

    summary = extract_smtp_messages(
        root,
        Path("tshark.exe"),
        capabilities=_capabilities(),
        max_attachment_bytes=4,
    )
    assert summary.status == "budget-limited"
    assert summary.skipped_attachment_budget == 1
    assert summary.messages[0].attachments[0].status == "skipped-budget"
    database = Database(root / "project.sqlite")
    with database.connect() as connection:
        assert connection.execute("SELECT count(*) FROM artifact").fetchone()[0] == 0
        assert connection.execute("SELECT status FROM smtp_attachment").fetchone()[0] == (
            "skipped-budget"
        )
