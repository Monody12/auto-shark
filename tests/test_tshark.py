from auto_shark.engines.tshark import (
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
