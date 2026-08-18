from pathlib import Path

from auto_shark.engines.stream import StreamProcessResult
from auto_shark.engines.tshark import TsharkCapabilities
from auto_shark.inventory import _protocol_analyzer_status, derive_coverage_status, index_summary
from auto_shark.project import create_project
from auto_shark.protocols.inventory import INVENTORY_FIELDS
from auto_shark.storage import Database


def _capabilities() -> TsharkCapabilities:
    return TsharkCapabilities(
        executable="tshark",
        version_line="TShark 4.6.7",
        fields=INVENTORY_FIELDS,
        protocols=("http", "telnet"),
        export_objects=(),
        features={"http": True, "telnet": True, "ftp": True, "multipart": True},
        missing_core_fields=(),
        usable=True,
        errors=(),
    )


def _row(**values: str) -> bytes:
    defaults = {
        "frame.time_epoch": "1.0",
        "frame.len": "60",
        "frame.cap_len": "60",
    }
    defaults.update(values)
    return "\t".join(defaults.get(field, "") for field in INVENTORY_FIELDS).encode()


def _project(tmp_path: Path) -> Path:
    capture = tmp_path / "capture.pcap"
    capture.write_bytes(b"pcap")
    root = tmp_path / "case.auto-shark"
    create_project(capture, root, allow_synced=True)
    return root


def _install_tshark(monkeypatch, rows: list[bytes], *, returncode: int = 0) -> None:
    monkeypatch.setattr("auto_shark.inventory.probe_tshark", lambda _: _capabilities())

    def run(argv, consume, **kwargs):
        for row in rows:
            consume(row)
        return StreamProcessResult(
            tuple(argv), returncode, len(rows), b"error" if returncode else b"", False,
            False, False,
        )

    monkeypatch.setattr("auto_shark.inventory.run_streaming_lines", run)
    monkeypatch.setattr(
        "auto_shark.findings.index_multipart_findings",
        lambda *args, **kwargs: type(
            "FindingSummary",
            (),
            {"multipart_parts": 0, "type_mismatch_findings": 0, "contradiction_findings": 0},
        )(),
    )
    monkeypatch.setattr(
        "auto_shark.manual_queue.rebuild_manual_queue",
        lambda *args, **kwargs: type("QueueSummary", (), {"tasks": 0, "signals": 0})(),
    )


def test_inventory_persists_ipv4_ipv6_roles_coverage_and_stable_rerun(
    tmp_path, monkeypatch
) -> None:
    root = _project(tmp_path)
    rows = [
        _row(
            **{
                "frame.number": "1",
                "frame.protocols": "eth:ip:tcp:telnet",
                "ip.src": "10.0.0.1",
                "ip.dst": "10.0.0.2",
                "tcp.stream": "0",
                "tcp.srcport": "40000",
                "tcp.dstport": "23",
                "tcp.len": "0",
                "tcp.flags.syn": "1",
            }
        ),
        _row(
            **{
                "frame.number": "2",
                "frame.time_epoch": "2.0",
                "frame.protocols": "eth:ip:tcp:telnet",
                "ip.src": "10.0.0.2",
                "ip.dst": "10.0.0.1",
                "tcp.stream": "0",
                "tcp.srcport": "23",
                "tcp.dstport": "40000",
                "tcp.len": "10",
                "tcp.flags.ack": "1",
            }
        ),
        _row(
            **{
                "frame.number": "3",
                "frame.time_epoch": "3.0",
                "frame.protocols": "eth:ipv6:udp:dns",
                "ipv6.src": "2001:db8::1",
                "ipv6.dst": "2001:db8::2",
                "udp.stream": "5",
                "udp.srcport": "50000",
                "udp.dstport": "53",
                "udp.length": "28",
            }
        ),
    ]
    _install_tshark(monkeypatch, rows)
    first = index_summary(root, Path("tshark"))
    second = index_summary(root, Path("tshark"))
    assert first.processed_frames == second.processed_frames == 3
    assert first.conversation_profiles == second.conversation_profiles == 2
    database = Database(root / "project.sqlite")
    with database.connect() as connection:
        profiles = connection.execute(
            "SELECT protocol,frame_count,payload_bytes,initiator_endpoint,"
            "responder_endpoint FROM conversation_profile ORDER BY protocol"
        ).fetchall()
        counts = {
            table: int(connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0])
            for table in (
                "capture_inventory_run",
                "protocol_observation",
                "conversation_profile",
                "conversation_profile_run",
            )
        }
    assert tuple(profiles[0]) == ("tcp", 2, 10, "10.0.0.1:40000", "10.0.0.2:23")
    assert tuple(profiles[1]) == ("udp", 1, 20, None, None)
    assert counts["capture_inventory_run"] == 2
    assert counts["protocol_observation"] == 7
    assert counts["conversation_profile"] == 2
    assert counts["conversation_profile_run"] == 4


def test_inventory_records_frame_label_conversation_and_missing_field_limits(
    tmp_path, monkeypatch
) -> None:
    root = _project(tmp_path)
    rows = [
        _row(
            **{
                "frame.number": "1",
                "frame.protocols": "eth:ip:tcp:http",
                "ip.src": "1.1.1.1",
                "ip.dst": "2.2.2.2",
                "tcp.stream": "0",
                "tcp.srcport": "1",
                "tcp.dstport": "2",
                "tcp.len": "1",
            }
        ),
        _row(
            **{
                "frame.number": "2",
                "frame.protocols": "eth:ip:tcp",
                "ip.src": "1.1.1.1",
                "ip.dst": "2.2.2.2",
                "tcp.stream": "1",
                "tcp.srcport": "1",
                "tcp.dstport": "2",
                "tcp.len": "1",
            }
        ),
        _row(
            **{
                "frame.number": "3",
                "frame.protocols": "eth:ip:tcp",
                "tcp.stream": "2",
                "tcp.len": "1",
            }
        ),
    ]
    _install_tshark(monkeypatch, rows)
    summary = index_summary(
        root,
        Path("tshark"),
        max_frames=2,
        max_protocol_labels=2,
        max_conversations=1,
    )
    assert summary.status == "budget-limited"
    assert summary.processed_frames == 2
    assert summary.skipped_frames == 1
    assert summary.skipped_conversations == 1
    assert summary.skipped_protocol_labels > 0
    database = Database(root / "project.sqlite")
    with database.connect() as connection:
        reasons = {
            str(row[0]) for row in connection.execute("SELECT reason FROM inventory_skip")
        }
    assert reasons == {"frame-limit", "label-limit", "conversation-limit"}


def test_inventory_persists_failed_tool_run(tmp_path, monkeypatch) -> None:
    root = _project(tmp_path)
    _install_tshark(monkeypatch, [], returncode=2)
    summary = index_summary(root, Path("tshark"))
    assert summary.status == "failed"
    database = Database(root / "project.sqlite")
    with database.connect() as connection:
        run = connection.execute(
            "SELECT status,exit_code,stderr_text FROM tool_run ORDER BY id DESC LIMIT 1"
        ).fetchone()
    assert tuple(run) == ("failed", 2, "error")


def test_coverage_precedence() -> None:
    assert derive_coverage_status(capability_available=False) == "unavailable"
    assert derive_coverage_status(capability_available=True, analyzer_status="failed") == "failed"
    assert (
        derive_coverage_status(capability_available=True, budget_limited=True)
        == "budget-limited"
    )
    assert derive_coverage_status(capability_available=True, analyzer_status="partial") == "partial"
    assert (
        derive_coverage_status(capability_available=True, analyzer_status="budget-limited")
        == "budget-limited"
    )
    assert (
        derive_coverage_status(capability_available=True, analyzer_status="complete")
        == "complete"
    )
    assert derive_coverage_status(capability_available=True) == "not-run"


def test_smtp_coverage_uses_latest_run_messages_and_skips(tmp_path) -> None:
    root = _project(tmp_path)
    database = Database(root / "project.sqlite")
    with database.connect() as connection:
        capture_id = int(connection.execute("SELECT id FROM capture").fetchone()[0])
        for run_id in ("smtp-old", "smtp-current"):
            connection.execute(
                "INSERT INTO tool_run"
                "(run_id,tool_name,argv_json,capability_json,started_at,status,exit_code) "
                "VALUES(?,'tshark','[]','{}','2026-08-18T00:00:00+00:00','completed',0)",
                (run_id,),
            )
        old_run_id, current_run_id = [
            int(row[0]) for row in connection.execute("SELECT id FROM tool_run ORDER BY id")
        ]
        connection.execute(
            "INSERT INTO smtp_skip"
            "(tool_run_id,tcp_stream,frame_number,reason,count,detail_json) "
            "VALUES(?,1,10,'data-not-reassembled',1,'{}')",
            (old_run_id,),
        )
        connection.execute(
            "INSERT INTO smtp_message"
            "(message_id,capture_id,tool_run_id,tcp_stream,direction,data_frame,final_frame,"
            "declared_length,status,updated_at) "
            "VALUES('message',?,?,2,'a:1>b:25',20,21,100,'complete',"
            "'2026-08-18T00:00:00+00:00')",
            (capture_id, current_run_id),
        )
        assert _protocol_analyzer_status(connection, capture_id, "smtp") == "complete"
        connection.execute(
            "INSERT INTO smtp_skip"
            "(tool_run_id,tcp_stream,frame_number,reason,count,detail_json) "
            "VALUES(?,3,30,'data-not-reassembled',1,'{}')",
            (current_run_id,),
        )
        assert _protocol_analyzer_status(connection, capture_id, "smtp") == "partial"
        connection.execute("DELETE FROM smtp_skip WHERE tool_run_id=?", (current_run_id,))
        connection.execute(
            "INSERT INTO smtp_skip"
            "(tool_run_id,reason,count,detail_json) VALUES(?,'attachment-budget',1,'{}')",
            (current_run_id,),
        )
        assert _protocol_analyzer_status(connection, capture_id, "smtp") == "budget-limited"
