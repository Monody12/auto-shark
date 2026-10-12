"""Regression guards for idempotent project access in the analyze stage.

``analyze_http`` used to call ``create_project`` unconditionally, which
raised ``FileExistsError`` on every GUI-driven run (the GUI creates the
project when a capture is opened, then the analyze stage runs on the same
directory) and left every HTTP page silently empty.
"""

from __future__ import annotations

import pytest

from auto_shark.analysis import open_or_create_project
from auto_shark.project import create_project


def test_open_or_create_reuses_existing_project_for_same_capture(tmp_path) -> None:
    capture = tmp_path / "cap.pcap"
    capture.write_bytes(b"pcap-bytes")
    project_dir = tmp_path / "gui-flow.auto-shark"

    created = create_project(capture, project_dir)
    # The GUI flow: analyze runs after the project already exists.
    reopened = open_or_create_project(capture, project_dir)
    assert reopened.root == created.root
    assert reopened.capture_sha256 == created.capture_sha256
    # And a re-run of the full analysis reuses it again.
    again = open_or_create_project(capture, project_dir)
    assert again.capture_sha256 == created.capture_sha256


def test_open_or_create_builds_fresh_project_when_manifest_missing(tmp_path) -> None:
    capture = tmp_path / "cap.pcap"
    capture.write_bytes(b"pcap-bytes")
    project_dir = tmp_path / "new.auto-shark"

    info = open_or_create_project(capture, project_dir)
    assert (project_dir / "project.json").is_file()
    assert info.capture_path == capture.resolve()


def test_open_or_create_rejects_project_belonging_to_other_capture(tmp_path) -> None:
    first = tmp_path / "first.pcap"
    first.write_bytes(b"first-bytes")
    project_dir = tmp_path / "case.auto-shark"
    create_project(first, project_dir)

    second = tmp_path / "second.pcap"
    second.write_bytes(b"second-bytes")
    with pytest.raises(ValueError, match="different capture"):
        open_or_create_project(second, project_dir)


def test_corrupt_capture_hint_appends_pcapfix_advice(tmp_path) -> None:
    from auto_shark.analysis import _corrupt_capture_hint

    broken = tmp_path / "broken.pcap"
    broken.write_bytes(b"not a pcap header at all")
    hint = _corrupt_capture_hint(broken, "tshark: the capture file appears to be damaged")
    assert "pcapfix" in hint

    good = tmp_path / "good.pcapng"
    good.write_bytes(bytes((0x0A, 0x0D, 0x0D, 0x0A)) + b"rest")
    clean = _corrupt_capture_hint(good, "some unrelated tshark error")
    assert clean == ""
