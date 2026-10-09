import json

import pytest

from auto_shark.project import (
    create_project,
    ensure_local_project_path,
    inspect_project,
    read_flag_format,
    write_flag_format,
)


def test_synced_project_path_is_rejected() -> None:
    with pytest.raises(ValueError, match="synced"):
        ensure_local_project_path("/sync/projects/sample.auto-shark", roots=["/sync"])


def test_project_create_and_inspect(tmp_path) -> None:
    capture = tmp_path / "sample.pcap"
    capture.write_bytes(b"fixture capture")
    project = tmp_path / "projects" / "sample.auto-shark"
    created = create_project(capture, project)
    reopened = inspect_project(project)
    assert reopened == created
    manifest = json.loads((project / "project.json").read_text(encoding="utf-8"))
    assert manifest["schema_version"] == "auto-shark-project/v1"
    assert (project / "project.sqlite").is_file()
    assert (project / "blobs").is_dir()


def test_flag_format_round_trip(tmp_path) -> None:
    capture = tmp_path / "cap.pcap"
    capture.write_bytes(b"pcap")
    info = create_project(capture, tmp_path / "case.auto-shark")

    assert read_flag_format(info.root) is None
    write_flag_format(info.root, r"SUCTF\{[^}]{1,128}\}")
    assert read_flag_format(info.root) == r"SUCTF\{[^}]{1,128}\}"
    write_flag_format(info.root, "   ")
    assert read_flag_format(info.root) is None
