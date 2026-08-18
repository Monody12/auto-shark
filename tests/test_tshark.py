import json

import pytest

from auto_shark.engines.tshark import (
    TLS_RSA_KEY_MAX_BYTES,
    TsharkCapabilities,
    load_tls_rsa_key,
    parse_export_objects,
    parse_field_registry,
    parse_protocol_registry,
)


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
