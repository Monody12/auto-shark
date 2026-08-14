import json
from pathlib import Path

import pytest

import auto_shark.tcp as tcp_module
import auto_shark.telnet as telnet_module
from auto_shark.core.ids import candidate_id
from auto_shark.engines.stream import StreamProcessResult
from auto_shark.engines.tshark import TsharkCapabilities
from auto_shark.project import create_project
from auto_shark.protocols.tcp import TCP_FIELDS
from auto_shark.protocols.telnet import TELNET_FIELDS, TELNET_REQUIRED_FIELDS
from auto_shark.queries import query_telnet_dialogues
from auto_shark.storage import Database
from auto_shark.telnet import _RecordBuilder, index_telnet


def _capabilities():
    fields = set(TCP_FIELDS) | set(TELNET_REQUIRED_FIELDS) | {"ip.src", "ip.dst"}
    return TsharkCapabilities(
        executable="fake-tshark",
        version_line="TShark fake",
        fields=tuple(sorted(fields)),
        protocols=("tcp", "telnet"),
        export_objects=(),
        features={"tcp_stream": True, "telnet": True},
        missing_core_fields=(),
        usable=True,
        errors=(),
    )


def _metadata_line(frame, source, source_port, destination, destination_port, text):
    values = {
        "frame.number": str(frame),
        "frame.time_epoch": f"{frame}.0",
        "frame.len": "100",
        "frame.cap_len": "100",
        "tcp.stream": "0",
        "ip.src": source,
        "ip.dst": destination,
        "tcp.srcport": str(source_port),
        "tcp.dstport": str(destination_port),
        "telnet.data": text,
    }
    return "\t".join(f'"{values.get(field, "")}"' for field in TELNET_FIELDS).encode()


def _with_stream(line, fields, stream_index, frame_delta=0):
    values = line.decode().split("\t")
    values[fields.index("tcp.stream")] = str(stream_index)
    values[fields.index("frame.number")] = str(
        int(values[fields.index("frame.number")].strip('"')) + frame_delta
    )
    return "\t".join(values).encode()


def _tcp_line(
    frame,
    source,
    source_port,
    destination,
    destination_port,
    sequence,
    payload,
    *,
    syn=False,
    ack=True,
):
    values = {
        "frame.number": str(frame),
        "frame.time_epoch": f"{frame}.0",
        "frame.cap_len": "100",
        "frame.len": "100",
        "ip.src": source,
        "tcp.srcport": str(source_port),
        "ip.dst": destination,
        "tcp.dstport": str(destination_port),
        "tcp.stream": "0",
        "tcp.seq": str(sequence),
        "tcp.seq_raw": str(1000 + sequence),
        "tcp.len": str(len(payload)),
        "tcp.payload": payload.hex(),
        "tcp.flags.syn": "1" if syn else "",
        "tcp.flags.ack": "1" if ack else "",
    }
    return "\t".join(values.get(field, "") for field in TCP_FIELDS).encode()


def _runner(lines):
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


def _project(tmp_path):
    capture = tmp_path / "capture.pcap"
    capture.write_bytes(b"capture")
    root = tmp_path / "telnet.auto-shark"
    create_project(capture, root)
    return root, Database(root / "project.sqlite")


def _lines():
    client = ("10.0.0.1", 1146, "10.0.0.2", 23)
    server = ("10.0.0.2", 23, "10.0.0.1", 1146)
    metadata = [
        _metadata_line(3, *server, "login: "),
        _metadata_line(4, *client, "user"),
    ]
    tcp = [
        _tcp_line(1, *client, 0, b"", syn=True, ack=False),
        _tcp_line(2, *server, 0, b"", syn=True, ack=True),
        _tcp_line(3, *server, 1, b"login: "),
        _tcp_line(4, *client, 1, b"user\r\n"),
        _tcp_line(5, *server, 8, b"user\r\nPassword: "),
        _tcp_line(6, *client, 7, b"secret\r\n"),
        _tcp_line(7, *server, 24, b"\xff"),
        _tcp_line(8, *server, 25, b"\xf2"),
        _tcp_line(9, *server, 26, b"^C"),
    ]
    return metadata, tcp


def test_index_telnet_persists_ranges_relations_and_reuses_blobs(tmp_path, monkeypatch) -> None:
    root, database = _project(tmp_path)
    metadata, tcp = _lines()
    monkeypatch.setattr(telnet_module, "run_streaming_lines", _runner(metadata))
    monkeypatch.setattr(tcp_module, "run_streaming_lines", _runner(tcp))

    first = index_telnet(root, Path("tshark"), capabilities=_capabilities())
    second = index_telnet(root, Path("tshark"), capabilities=_capabilities())

    assert first == second
    assert first.complete == 1
    assert first.records == 7
    assert first.parsed_bytes == 41
    assert first.skipped_bytes == 0
    with database.connect() as connection:
        counts = {
            table: int(connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0])
            for table in (
                "blob",
                "telnet_dialogue",
                "telnet_dialogue_run",
                "telnet_record",
                "telnet_record_source",
                "telnet_record_relation",
                "telnet_parse_skip",
            )
        }
        dialogue = connection.execute(
            "SELECT status,client_endpoint,server_endpoint FROM telnet_dialogue"
        ).fetchone()
        records = connection.execute(
            "SELECT direction_role,record_kind,stream_offset,byte_length,semantic_label,"
            "command,frame_start,frame_end FROM telnet_record "
            "ORDER BY frame_start,time_start,direction_role,stream_offset"
        ).fetchall()
        relations = [
            tuple(row)
            for row in connection.execute(
                "SELECT source.semantic_label,target.semantic_label,rel.relation "
                "FROM telnet_record_relation rel "
                "JOIN telnet_record source ON source.id=rel.record_id "
                "JOIN telnet_record target ON target.id=rel.related_record_id "
                "ORDER BY rel.relation,source.id"
            )
        ]
        coverage = connection.execute(
            "SELECT direction_role,sum(byte_length) FROM telnet_record GROUP BY direction_role"
        ).fetchall()
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
    assert counts == {
        "blob": 9,
        "telnet_dialogue": 1,
        "telnet_dialogue_run": 2,
        "telnet_record": 7,
        "telnet_record_source": 8,
        "telnet_record_relation": 3,
        "telnet_parse_skip": 0,
    }
    assert tuple(dialogue) == ("complete", "10.0.0.1:1146", "10.0.0.2:23")
    assert [tuple(row) for row in coverage] == [("client", 14), ("server", 27)]
    assert any(tuple(row[0:4]) == ("server", "command", 23, 2) for row in records)
    assert relations == [
        ("line", "line", "echo-of"),
        ("line", "prompt:login", "responds-to"),
        ("line", "prompt:password", "responds-to"),
    ]
    assert list((root / "jobs").iterdir()) == []


def test_record_builder_keeps_cr_nul_in_one_bounded_application_record(tmp_path) -> None:
    blob = tmp_path / "stream.bin"
    blob.write_bytes(b"value\r\x00next")
    builder = _RecordBuilder(blob, "client", max_record_bytes=100, max_records=10)

    builder.add(telnet_module.TelnetByteRecord("application", 0, 11))
    records = builder.finish()

    assert [(item.start, item.end, item.semantic_label) for item in records] == [
        (0, 7, "line"),
        (7, 11, None),
    ]


def test_index_telnet_persists_record_budget_skip(tmp_path, monkeypatch) -> None:
    root, database = _project(tmp_path)
    metadata, tcp = _lines()
    monkeypatch.setattr(telnet_module, "run_streaming_lines", _runner(metadata))
    monkeypatch.setattr(tcp_module, "run_streaming_lines", _runner(tcp))

    summary = index_telnet(
        root,
        Path("tshark"),
        capabilities=_capabilities(),
        max_records=1,
    )

    assert summary.truncated == 1
    assert summary.records == 1
    assert summary.parsed_bytes + summary.skipped_bytes == 41
    with database.connect() as connection:
        skips = [
            tuple(row)
            for row in connection.execute(
                "SELECT stream_offset,byte_length,reason FROM telnet_parse_skip "
                "ORDER BY reconstruction_id"
            )
        ]
        policy = json.loads(
            connection.execute("SELECT policy_json FROM telnet_dialogue_run").fetchone()[0]
        )
    assert skips == [(6, 8, "record-limit"), (0, 27, "record-limit")]
    assert policy["max_records"] == 1


def test_index_telnet_persists_each_metadata_frame_limit_skip(tmp_path, monkeypatch) -> None:
    root, database = _project(tmp_path)
    metadata, tcp = _lines()
    monkeypatch.setattr(telnet_module, "run_streaming_lines", _runner(metadata))
    monkeypatch.setattr(tcp_module, "run_streaming_lines", _runner(tcp))

    summary = index_telnet(
        root,
        Path("tshark"),
        capabilities=_capabilities(),
        max_metadata_frames=1,
    )

    assert summary.metadata_frames == 1
    assert summary.skipped_metadata_frames == 1
    assert summary.truncated == 1
    assert summary.records == summary.parsed_bytes == 0
    assert summary.skipped_bytes == 41
    with database.connect() as connection:
        row = connection.execute(
            "SELECT frame_number,stream_index,reason FROM telnet_metadata_skip"
        ).fetchone()
        parse_skips = list(
            connection.execute(
                "SELECT byte_length,reason FROM telnet_parse_skip ORDER BY reconstruction_id"
            )
        )
    assert tuple(row) == (4, 0, "frame-limit")
    assert [tuple(skip) for skip in parse_skips] == [
        (14, "metadata-limit"),
        (27, "metadata-limit"),
    ]


def test_index_telnet_stream_limit_persists_reconstructed_ranges(tmp_path, monkeypatch) -> None:
    root, database = _project(tmp_path)
    metadata, tcp = _lines()
    second_metadata = _with_stream(metadata[0], TELNET_FIELDS, 1, 100)
    second_tcp = [_with_stream(line, TCP_FIELDS, 1, 100) for line in tcp]
    monkeypatch.setattr(
        telnet_module, "run_streaming_lines", _runner([*metadata, second_metadata])
    )

    def tcp_runner(argv, on_line, **kwargs):
        del kwargs
        lines = second_tcp if "tcp.stream == 1" in argv else tcp
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

    monkeypatch.setattr(tcp_module, "run_streaming_lines", tcp_runner)

    summary = index_telnet(
        root,
        Path("tshark"),
        capabilities=_capabilities(),
        max_streams=1,
    )

    assert summary.streams == 2
    assert summary.complete == summary.truncated == 1
    assert summary.parsed_bytes == summary.skipped_bytes == 41
    with database.connect() as connection:
        skipped = connection.execute(
            "SELECT tdr.skipped_bytes,count(tps.id) "
            "FROM telnet_dialogue_run tdr "
            "JOIN telnet_parse_skip tps ON tps.dialogue_run_id=tdr.id "
            "JOIN telnet_dialogue td ON td.id=tdr.dialogue_id "
            "JOIN conversation c ON c.id=td.conversation_id "
            "WHERE c.stream_index=1 GROUP BY tdr.id"
        ).fetchone()
        ranges = list(
            connection.execute(
                "SELECT tps.byte_length,tps.reason FROM telnet_parse_skip tps "
                "JOIN telnet_dialogue_run tdr ON tdr.id=tps.dialogue_run_id "
                "JOIN telnet_dialogue td ON td.id=tdr.dialogue_id "
                "JOIN conversation c ON c.id=td.conversation_id "
                "WHERE c.stream_index=1 ORDER BY tps.reconstruction_id"
            )
        )
    assert tuple(skipped) == (41, 2)
    assert [tuple(row) for row in ranges] == [(14, "stream-limit"), (27, "stream-limit")]


def test_index_telnet_persists_parser_failure_without_partial_records(
    tmp_path, monkeypatch
) -> None:
    root, database = _project(tmp_path)
    metadata, tcp = _lines()
    monkeypatch.setattr(telnet_module, "run_streaming_lines", _runner(metadata))
    monkeypatch.setattr(tcp_module, "run_streaming_lines", _runner(tcp))
    monkeypatch.setattr(
        telnet_module,
        "_parse_records",
        lambda *args, **kwargs: (_ for _ in ()).throw(ValueError("synthetic parser failure")),
    )

    summary = index_telnet(root, Path("tshark"), capabilities=_capabilities())

    assert summary.failed == 1
    assert summary.records == summary.parsed_bytes == 0
    assert summary.skipped_bytes == 41
    with database.connect() as connection:
        dialogue = connection.execute("SELECT status,error FROM telnet_dialogue").fetchone()
        run = connection.execute(
            "SELECT status,record_count,parsed_bytes,skipped_bytes,error "
            "FROM telnet_dialogue_run"
        ).fetchone()
        records = connection.execute("SELECT count(*) FROM telnet_record").fetchone()[0]
        skip_bytes = connection.execute(
            "SELECT sum(byte_length) FROM telnet_parse_skip"
        ).fetchone()[0]
    assert tuple(dialogue) == ("failed", "synthetic parser failure")
    assert tuple(run) == ("failed", 0, 0, 41, "synthetic parser failure")
    assert records == 0 and skip_bytes == 41


def test_index_telnet_keeps_unresolved_role_without_port_guess(tmp_path, monkeypatch) -> None:
    root, database = _project(tmp_path)
    metadata, tcp = _lines()
    monkeypatch.setattr(telnet_module, "run_streaming_lines", _runner(metadata))
    capabilities = _capabilities()
    without_ack = TsharkCapabilities(
        executable=capabilities.executable,
        version_line=capabilities.version_line,
        fields=tuple(field for field in capabilities.fields if field != "tcp.flags.ack"),
        protocols=capabilities.protocols,
        export_objects=capabilities.export_objects,
        features=capabilities.features,
        missing_core_fields=capabilities.missing_core_fields,
        usable=True,
        errors=(),
    )
    selected = tuple(field for field in TCP_FIELDS if field != "tcp.flags.ack")
    projected = []
    for line in tcp:
        values = dict(zip(TCP_FIELDS, line.decode().split("\t")))
        projected.append("\t".join(values[field] for field in selected).encode())
    monkeypatch.setattr(tcp_module, "run_streaming_lines", _runner(projected))

    summary = index_telnet(root, Path("tshark"), capabilities=without_ack)

    assert summary.unresolved_role == 1
    assert summary.records == summary.parsed_bytes == 0
    assert summary.skipped_bytes == 41
    with database.connect() as connection:
        dialogue = connection.execute(
            "SELECT status,client_endpoint,server_endpoint FROM telnet_dialogue"
        ).fetchone()
        skip_bytes = connection.execute(
            "SELECT sum(byte_length) FROM telnet_parse_skip"
        ).fetchone()[0]
    assert tuple(dialogue) == ("unresolved-role", None, None)
    assert skip_bytes == 41


def test_telnet_query_is_bounded_deterministic_and_links_candidates(tmp_path, monkeypatch) -> None:
    root, database = _project(tmp_path)
    metadata, tcp = _lines()
    monkeypatch.setattr(telnet_module, "run_streaming_lines", _runner(metadata))
    monkeypatch.setattr(tcp_module, "run_streaming_lines", _runner(tcp))
    index_telnet(root, Path("tshark"), capabilities=_capabilities())
    with database.connect() as connection:
        client_record = connection.execute(
            "SELECT tr.evidence_id,e.capture_id,e.blob_id,e.direction "
            "FROM telnet_record tr JOIN evidence e ON e.id=tr.evidence_id "
            "WHERE tr.direction_role='client' AND tr.stream_offset=6"
        ).fetchone()
        connection.execute(
            "INSERT INTO evidence "
            "(evidence_id,capture_id,source_kind,frame_start,frame_end,direction,"
            "byte_offset,byte_length,text_value,blob_id,locator_json) "
            "VALUES ('match',?,'flag-match',6,6,?,6,6,'secret',?,'{}')",
            (client_record["capture_id"], client_record["direction"], client_record["blob_id"]),
        )
        match_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
        public_id = candidate_id("flag", "secret")
        connection.execute(
            "INSERT INTO candidate "
            "(candidate_id,kind,raw_value,normalized_value,confidence,rank_score,created_at) "
            "VALUES (?,'flag','secret','secret',0.9,90,'now')",
            (public_id,),
        )
        candidate_db_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
        connection.execute(
            "INSERT INTO candidate_evidence (candidate_id,evidence_id,role) "
            "VALUES (?,?,'direct-match')",
            (candidate_db_id, match_id),
        )

    first = query_telnet_dialogues(
        root,
        stream=0,
        max_records_per_dialogue=20,
        max_preview_bytes=64,
        max_total_preview_bytes=1024,
    )
    second = query_telnet_dialogues(
        root,
        stream=0,
        max_records_per_dialogue=20,
        max_preview_bytes=64,
        max_total_preview_bytes=1024,
    )

    assert first.to_json() == second.to_json()
    assert first.total == first.count == 1
    item = first.items[0]
    assert item["current"] is True
    assert item["endpoints"]["client"] == "10.0.0.1:1146"
    assert item["total_records"] == item["record_count"] == 7
    command = next(record for record in item["records"] if record["kind"] == "command")
    assert command["range"] == {"start": 23, "end": 25, "byte_length": 2}
    assert command["command"] == 242
    assert command["preview"] == r"\xff\xf2"
    assert command["sources"] == [
        {"frame": 7, "record_offset": 0, "stream_offset": 23, "byte_length": 1},
        {"frame": 8, "record_offset": 1, "stream_offset": 24, "byte_length": 1},
    ]
    password = next(
        record
        for record in item["records"]
        if record["direction_role"] == "client" and record["range"]["start"] == 6
    )
    assert password["preview"] == r"secret\r\n"
    assert password["candidates"][0]["candidate_id"] == public_id
    assert password["relations"][0]["relation"] == "responds-to"
    assert query_telnet_dialogues(root, stream=99).items == ()

    bounded = query_telnet_dialogues(
        root,
        max_records_per_dialogue=2,
        max_preview_bytes=2,
        max_total_preview_bytes=3,
    )
    assert bounded.items[0]["record_count"] == 2
    assert bounded.items[0]["records_truncated"] is True
    assert bounded.preview_bytes == 3
    assert all(record["preview_truncated"] for record in bounded.items[0]["records"])
    auxiliary_bounded = query_telnet_dialogues(
        root,
        max_records_per_dialogue=20,
        max_preview_bytes=64,
        max_total_preview_bytes=1024,
        max_source_mappings=1,
        max_relations=1,
        max_candidates=1,
    )
    records = auxiliary_bounded.items[0]["records"]
    assert sum(record["source_count"] for record in records) == 8
    assert sum(len(record["sources"]) for record in records) == 1
    assert any(record["sources_truncated"] for record in records)
    with pytest.raises(ValueError, match="stream index"):
        query_telnet_dialogues(root, stream=-1)
    with pytest.raises(ValueError, match="positive"):
        query_telnet_dialogues(root, max_preview_bytes=0)
    with pytest.raises(ValueError, match="cannot exceed"):
        query_telnet_dialogues(root, max_records_per_dialogue=10_001)
