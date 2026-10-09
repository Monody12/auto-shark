import json

import pytest

from auto_shark.engines.tshark import (
    TLS_RSA_KEY_MAX_BYTES,
    TSHARK_TOO_OLD_TEMPLATE,
    TsharkCapabilities,
    format_tshark_too_old,
    load_tls_rsa_key,
    parse_export_objects,
    parse_field_registry,
    parse_protocol_registry,
    tshark_too_old,
)


def test_tshark_too_old_helper_explains_the_floor() -> None:
    assert tshark_too_old((2, 2, 1)) is True
    assert tshark_too_old((3, 6, 2)) is True
    assert tshark_too_old((4, 0, 0)) is False
    assert tshark_too_old((4, 6, 7)) is False
    assert tshark_too_old(None) is False
    message = format_tshark_too_old((2, 2, 1))
    assert "2.2.1" in message
    assert "4.0" in message
    assert message == TSHARK_TOO_OLD_TEMPLATE.format(found="2.2.1")


def test_registry_parsers_use_structured_columns() -> None:
    fields = "F\tStream index\ttcp.stream\tFT_UINT32\ttcp\nP\tTCP\ttcp\n"
    protocols = "Transmission Control Protocol\tTCP\ttcp\n"
    assert parse_field_registry(fields) == {"tcp.stream"}
    assert parse_protocol_registry(protocols) == {"tcp"}


def test_export_parser_ignores_explanatory_lines() -> None:
    text = "Available export object types:\n     http\n     ftp-data\n"
    assert parse_export_objects(text) == {"http", "ftp-data"}


def test_capability_provenance_is_stable_and_bounded() -> None:
    capabilities = TsharkCapabilities(
        executable="/opt/wireshark/tshark",
        version_line="TShark 4.6.7",
        fields=tuple(f"protocol.field_{index:06d}" for index in range(100_000)),
        protocols=("dns", "http", "tcp"),
        export_objects=("ftp-data", "http"),
        features={"http": True, "telnet": False},
        missing_core_fields=(),
        usable=True,
        errors=(),
    )

    first = capabilities.to_provenance_json()
    second = capabilities.to_provenance_json()
    payload = json.loads(first)

    assert first == second
    assert len(first.encode("utf-8")) < 2_048
    assert payload["schema_version"] == "auto-shark.tshark-capability/v1"
    assert payload["registries"]["fields"]["count"] == 100_000
    assert len(payload["registries"]["fields"]["sha256"]) == 64
    assert "protocol.field_000000" not in first
    assert "protocol.field_099999" not in first
    assert "protocol.field_000000" in capabilities.to_json()


def test_tls_rsa_key_arguments_and_provenance_redact_local_path(tmp_path) -> None:
    path = tmp_path / "challenge key.pem"
    path.write_bytes(b"synthetic challenge private key")
    key = load_tls_rsa_key(path)
    argv = ["tshark", *key.arguments, "-r", "capture.pcap"]

    assert key.path == path.resolve()
    assert key.byte_length == 31
    assert key.path.as_posix() in key.preference_value
    redacted = json.dumps(key.redact_argv(argv))
    assert str(key.path) not in redacted
    assert key.path.as_posix() not in redacted
    assert key.sha256 in redacted

    capabilities = TsharkCapabilities(
        executable="tshark",
        version_line="TShark test",
        fields=(),
        protocols=(),
        export_objects=(),
        features={"http": True},
        missing_core_fields=(),
        usable=True,
        errors=(),
    )
    provenance = json.loads(capabilities.to_provenance_json(tls_rsa_key=key))
    assert provenance["tls_rsa_key"] == {
        "byte_length": 31,
        "sha256": key.sha256,
    }
    assert key.path.as_posix() not in json.dumps(provenance)


@pytest.mark.parametrize("size", [0, TLS_RSA_KEY_MAX_BYTES + 1])
def test_tls_rsa_key_rejects_empty_or_oversized_files(tmp_path, size) -> None:
    path = tmp_path / "key.pem"
    path.write_bytes(b"x" * size)

    with pytest.raises(ValueError, match="TLS RSA private key"):
        load_tls_rsa_key(path)


def test_tls_rsa_key_rejects_missing_file(tmp_path) -> None:
    with pytest.raises(FileNotFoundError):
        load_tls_rsa_key(tmp_path / "missing.pem")


def test_find_tshark_rejects_ancient_discovered_copies(tmp_path, monkeypatch) -> None:
    """A discovered 2.x build must be skipped, an explicit path always wins."""

    from auto_shark.engines.tshark import find_tshark

    ancient = tmp_path / "tshark.exe"
    ancient.write_bytes(b"")
    monkeypatch.delenv("AUTO_SHARK_TSHARK", raising=False)
    monkeypatch.setattr(
        "auto_shark.engines.tshark.discover_tshark_candidates",
        lambda explicit=None, extra_dirs=(): ([ancient] if explicit is None else [ancient]),
    )
    monkeypatch.setattr(
        "auto_shark.engines.tshark._tshark_version", lambda _p: (2, 2, 1)
    )
    assert find_tshark(None) is None

    monkeypatch.setattr(
        "auto_shark.engines.tshark._tshark_version", lambda _p: (4, 6, 7)
    )
    assert find_tshark(None) == ancient

    # An explicit path is respected even when the version is unsupported.
    monkeypatch.setattr(
        "auto_shark.engines.tshark._tshark_version", lambda _p: (2, 2, 1)
    )
    assert find_tshark(ancient) == ancient


def test_tls_keylog_load_validate_and_redact(tmp_path) -> None:
    from auto_shark.engines.tshark import load_tls_keylog

    keylog = tmp_path / "ssl_keys.log"
    keylog.write_bytes(
        b"# comment line\n"
        b"CLIENT_HANDSHAKE_TRAFFIC_SECRET "
        b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef deadbeef\n"
    )
    loaded = load_tls_keylog(keylog)
    assert loaded.byte_length == keylog.stat().st_size
    assert loaded.arguments == ("-o", f"tls.keylog_file:{loaded.path}")
    redacted = loaded.redact_argv(list(loaded.arguments))
    assert str(loaded.path) not in redacted[1]
    assert loaded.sha256[:16] in redacted[1]

    not_keylog = tmp_path / "ssl_keys_not.log"
    not_keylog.write_bytes(b"just some text without labels\n")
    with pytest.raises(ValueError, match="no recognized key lines"):
        load_tls_keylog(not_keylog)

    oversized = tmp_path / "big.log"
    oversized.write_bytes(b"CLIENT_RANDOM " + b"x" * (1024 * 1024 + 10))
    with pytest.raises(ValueError, match="exceeds"):
        load_tls_keylog(oversized)


def test_find_tls_keylog_auto_detects_sibling(tmp_path) -> None:
    from auto_shark.engines.tshark import find_tls_keylog

    assert find_tls_keylog(tmp_path / "capture.pcapng") is None
    (tmp_path / "ssl_keys.log").write_bytes(
        b"CLIENT_RANDOM " + b"a" * 64 + b" " + b"b" * 64 + b"\n"
    )
    found = find_tls_keylog(tmp_path / "capture.pcapng")
    assert found is not None
    assert found.path.name == "ssl_keys.log"
