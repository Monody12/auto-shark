from typing import Optional

from auto_shark.analysis import _pair_http, _record_message
from auto_shark.protocols.http import HttpMessage
from auto_shark.storage import Database

CAPTURE_SHA = "b" * 64


def _message(frame: int, kind: str, linked: Optional[int] = None) -> HttpMessage:
    return HttpMessage(
        frame_number=frame,
        time_epoch=str(frame),
        frame_length=100,
        captured_length=100,
        tcp_stream=1,
        source="192.0.2.1" if kind == "request" else "192.0.2.2",
        destination="192.0.2.2" if kind == "request" else "192.0.2.1",
        source_port=50000 if kind == "request" else 80,
        destination_port=80 if kind == "request" else 50000,
        kind=kind,
        method="GET" if kind == "request" else None,
        uri="/" if kind == "request" else None,
        full_uri=None,
        host=None,
        response_code=200 if kind == "response" else None,
        response_phrase="OK" if kind == "response" else None,
        response_in_frame=linked if kind == "request" else None,
        request_in_frame=linked if kind == "response" else None,
        content_length=0,
        content_type=None,
    )


def test_pairing_preserves_matched_unmatched_and_orphan(tmp_path) -> None:
    database = Database(tmp_path / "project.sqlite")
    database.initialize()
    with database.connect() as connection:
        connection.execute(
            "INSERT INTO capture "
            "(capture_id, source_name, source_path, byte_length, sha256, created_at) "
            "VALUES ('capture', 'x', 'x', 1, ?, 'now')",
            (CAPTURE_SHA,),
        )
        capture_id = int(connection.execute("SELECT id FROM capture").fetchone()[0])
        _record_message(connection, capture_id, CAPTURE_SHA, _message(1, "request", 2))
        _record_message(connection, capture_id, CAPTURE_SHA, _message(2, "response", 1))
        _record_message(connection, capture_id, CAPTURE_SHA, _message(3, "request"))
        _record_message(connection, capture_id, CAPTURE_SHA, _message(4, "response"))
        _pair_http(connection, capture_id, CAPTURE_SHA)
        statuses = dict(
            connection.execute(
                "SELECT status, count(*) FROM transaction_record GROUP BY status"
            ).fetchall()
        )
        assert statuses == {"matched": 1, "orphan-response": 1, "unmatched-request": 1}
        assert connection.execute("SELECT count(*) FROM transaction_message").fetchone()[0] == 4
