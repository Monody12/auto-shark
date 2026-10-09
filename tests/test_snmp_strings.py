"""SNMP variable-binding string extraction."""

from __future__ import annotations

import binascii

from auto_shark.engines.stream import StreamProcessResult
from auto_shark.engines.tshark import TsharkCapabilities
from auto_shark.project import create_project
from auto_shark.snmp_strings import triage_snmp_strings
from auto_shark.storage import Database
from auto_shark.triage import triage_project


def _capabilities(with_octets: bool = True) -> TsharkCapabilities:
    fields = ("frame.number", "snmp.community")
    if with_octets:
        fields += ("snmp.value.octets",)
    return TsharkCapabilities(
        executable="fake-tshark",
        version_line="TShark test",
        fields=fields,
        protocols=("snmp",),
        export_objects=(),
        features={},
        missing_core_fields=(),
        usable=True,
        errors=(),
    )


def test_snmp_strings_stores_flag_and_triage_finds_it(tmp_path, monkeypatch) -> None:
    capture = tmp_path / "snmp.pcap"
    capture.write_bytes(b"pcap")
    root = tmp_path / "snmp.auto-shark"
    create_project(capture, root, allow_synced=True)
    monkeypatch.setattr("auto_shark.snmp_strings.probe_tshark", lambda _p: _capabilities())

    flag_hex = binascii.hexlify(b"flag{snmp-exfil-ok}")
    filler_hex = binascii.hexlify(b"Linux webshell 2.6.32")

    def fake_run(_argv, on_line, **_kwargs):
        on_line(b"11\tpublic\t" + filler_hex)
        on_line(b"12\tpublic\t" + flag_hex)
        on_line(b"13\tpublic\t")  # no values: skipped
        return StreamProcessResult((), 0, 2, b"", False, False, False)

    monkeypatch.setattr("auto_shark.snmp_strings.run_streaming_lines", fake_run)
    executable = tmp_path / "tshark.exe"
    executable.write_bytes(b"")

    summary = triage_snmp_strings(root, executable)

    assert summary.status == "stored"
    assert summary.frames == 2
    with Database(root / "project.sqlite").connect() as connection:
        row = connection.execute(
            "SELECT e.text_value FROM evidence e WHERE e.source_kind='snmp-strings'"
        ).fetchone()
        assert row is not None and "flag{snmp-exfil-ok}" in row[0]

    triage_summary = triage_project(root)
    assert triage_summary.known_matches >= 1


def test_snmp_strings_reports_no_traffic_or_capability(tmp_path, monkeypatch) -> None:
    capture = tmp_path / "plain.pcap"
    capture.write_bytes(b"pcap")
    root = tmp_path / "plain.auto-shark"
    create_project(capture, root, allow_synced=True)

    monkeypatch.setattr(
        "auto_shark.snmp_strings.probe_tshark", lambda _p: _capabilities(with_octets=False)
    )
    summary = triage_snmp_strings(root, tmp_path / "tshark.exe")
    assert summary.status == "unavailable"

    monkeypatch.setattr("auto_shark.snmp_strings.probe_tshark", lambda _p: _capabilities())
    monkeypatch.setattr(
        "auto_shark.snmp_strings.run_streaming_lines",
        lambda _a, _b, **_k: StreamProcessResult((), 0, 0, b"", False, False, False),
    )
    summary = triage_snmp_strings(root, tmp_path / "tshark.exe")
    assert summary.status == "no-snmp-strings"
