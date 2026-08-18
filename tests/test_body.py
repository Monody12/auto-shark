import json

import pytest

from auto_shark.body import _classify_body, _parse_batch_body_line, extract_http_bodies_batch
from auto_shark.engines.stream import StreamProcessResult
from auto_shark.engines.tshark import TsharkCapabilities, load_tls_rsa_key
from auto_shark.project import create_project
from auto_shark.storage import Database


def _capabilities() -> TsharkCapabilities:
    return TsharkCapabilities(
        executable="fake-tshark",
        version_line="TShark test",
        fields=(),
        protocols=(),
        export_objects=(),
        features={"http": True},
        missing_core_fields=(),
        usable=True,
        errors=(),
    )


def _project_with_http_messages(tmp_path):
    capture = tmp_path / "capture.pcap"
    capture.write_bytes(b"pcap")
    root = tmp_path / "case.auto-shark"
    create_project(capture, root, allow_synced=True)
    database = Database(root / "project.sqlite")
    with database.connect() as connection:
        capture_id = int(connection.execute("SELECT id FROM capture").fetchone()[0])
        for frame, kind, length in (
            (1, "response", None),
            (2, "request", 3),
            (3, "response", 1),
        ):
            connection.execute(
                "INSERT INTO frame(capture_id,frame_number) VALUES(?,?)",
                (capture_id, frame),
            )
            connection.execute(
                "INSERT INTO protocol_message "
                "(message_id,capture_id,representative_frame,protocol,message_kind,fields_json) "
                "VALUES(?,?,?,'http',?,'{}')",
                (f"message-{frame}", capture_id, frame, kind),
            )
            message_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
            connection.execute(
                "INSERT INTO http_message(protocol_message_id,content_length) VALUES(?,?)",
                (message_id, length),
            )
    return root, database


def test_batch_body_extraction_shares_provenance_and_handles_missing(
    tmp_path, monkeypatch
) -> None:
    root, database = _project_with_http_messages(tmp_path)
    calls = []

    def run(argv, on_line, **_kwargs):
        calls.append(tuple(argv))
        on_line(b'"1"\t"<MISSING>"')
        on_line(b'"2"\t"414243"')
        return StreamProcessResult(tuple(argv), 0, 2, b"", False, False, False)

    monkeypatch.setattr("auto_shark.body.run_streaming_lines", run)

    summary = extract_http_bodies_batch(
        root,
        [1, 2],
        tmp_path / "tshark",
        max_body_bytes=100,
        max_total_bytes=100,
        capabilities=_capabilities(),
    )

    assert len(calls) == 1
    statuses = [
        (item.frame_number, item.status, item.extracted_length) for item in summary.statuses
    ]
    assert statuses == [
        (1, "absent", 0),
        (2, "complete", 3),
    ]
    assert summary.skipped_frames == ()
    with database.connect() as connection:
        rows = connection.execute(
            "SELECT pm.representative_frame,hb.status,hb.extracted_length,hb.tool_run_id "
            "FROM http_body hb JOIN protocol_message pm ON pm.id=hb.protocol_message_id "
            "ORDER BY pm.representative_frame"
        ).fetchall()
        assert [(row[0], row[1], row[2]) for row in rows] == [
            (1, "absent", 0),
            (2, "complete", 3),
        ]
        assert len({row[3] for row in rows}) == 1
        assert connection.execute("SELECT count(*) FROM tool_run").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM blob").fetchone()[0] == 1
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_batch_body_parser_accepts_large_bounded_hex_field() -> None:
    data = b"A" * 70_000

    frame, decoded = _parse_batch_body_line(b'"7"\t"' + data.hex().encode() + b'"')

    assert frame == 7
    assert decoded == data


@pytest.mark.parametrize("line", [b'"7"\t', b'"7"\t"<MISSING>"'])
def test_batch_body_parser_accepts_both_tshark_empty_forms(line) -> None:
    assert _parse_batch_body_line(line) == (7, b"")


def test_batch_body_extraction_enforces_total_budget(tmp_path, monkeypatch) -> None:
    root, database = _project_with_http_messages(tmp_path)

    def run(argv, on_line, **_kwargs):
        on_line(b'"2"\t"414243"')
        on_line(b'"3"\t"44"')
        return StreamProcessResult(tuple(argv), 0, 2, b"", False, False, False)

    monkeypatch.setattr("auto_shark.body.run_streaming_lines", run)

    summary = extract_http_bodies_batch(
        root,
        [2, 3],
        tmp_path / "tshark",
        max_body_bytes=100,
        max_total_bytes=2,
        capabilities=_capabilities(),
    )

    statuses = [
        (item.frame_number, item.status, item.extracted_length) for item in summary.statuses
    ]
    assert statuses == [(2, "limit-truncated", 2)]
    assert summary.skipped_frames == (3,)
    with database.connect() as connection:
        rows = connection.execute(
            "SELECT pm.representative_frame,hb.status,hb.extracted_length "
            "FROM http_body hb JOIN protocol_message pm ON pm.id=hb.protocol_message_id"
        ).fetchall()
    assert [tuple(row) for row in rows] == [(2, "limit-truncated", 2)]


def test_batch_body_tls_key_is_used_but_path_is_redacted(tmp_path, monkeypatch) -> None:
    root, database = _project_with_http_messages(tmp_path)
    key_path = tmp_path / "challenge.pem"
    key_path.write_bytes(b"synthetic key")
    key = load_tls_rsa_key(key_path)
    calls = []

    def run(argv, on_line, **_kwargs):
        calls.append(tuple(argv))
        on_line(b'"1"\t"<MISSING>"')
        return StreamProcessResult(tuple(argv), 0, 1, b"", False, False, False)

    monkeypatch.setattr("auto_shark.body.run_streaming_lines", run)

    extract_http_bodies_batch(
        root,
        [1],
        tmp_path / "tshark",
        max_body_bytes=100,
        max_total_bytes=100,
        capabilities=_capabilities(),
        tls_rsa_key=key,
    )

    assert key.preference_value in calls[0]
    with database.connect() as connection:
        argv_json, capability_json = connection.execute(
            "SELECT argv_json,capability_json FROM tool_run"
        ).fetchone()
    assert key.path.as_posix() not in argv_json
    assert key.sha256 in argv_json
    assert key.path.as_posix() not in capability_json
    assert json.loads(capability_json)["tls_rsa_key"]["sha256"] == key.sha256


@pytest.mark.parametrize(
    ("declared", "actual", "truncated", "expected"),
    [
        (10, 10, False, "complete"),
        (None, 10, False, "complete"),
        (0, 0, False, "empty"),
        (None, 0, False, "absent"),
        (10, 0, False, "missing"),
        (10, 5, False, "partial"),
        (5, 10, False, "length-mismatch"),
        (10, 5, True, "limit-truncated"),
    ],
)
def test_body_status_classification(declared, actual, truncated, expected) -> None:
    assert _classify_body(declared, actual, truncated) == expected
