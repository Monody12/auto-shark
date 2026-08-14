from pathlib import Path

import pytest

from auto_shark.protocols.telnet import (
    TELNET_FIELDS,
    TELNET_REQUIRED_FIELDS,
    parse_telnet_line,
    selected_telnet_fields,
    tshark_telnet_arguments,
)


def _row(values, fields=TELNET_FIELDS):
    return "\t".join(f'"{values.get(field, "")}"' for field in fields).encode()


def _values():
    return {
        "frame.number": "39",
        "frame.time_epoch": "26.114445000",
        "frame.len": "64",
        "frame.cap_len": "64",
        "tcp.stream": "0",
        "ip.src": "192.0.2.2",
        "ip.dst": "192.0.2.1",
        "tcp.srcport": "23",
        "tcp.dstport": "1146",
        "telnet.data": "Password: ",
    }


def test_parse_telnet_line_uses_structured_metadata_without_data_decoding() -> None:
    frame = parse_telnet_line(_row(_values()))

    assert frame.frame_number == 39
    assert frame.stream_index == 0
    assert frame.source == "192.0.2.2"
    assert frame.destination_port == 1146


def test_parse_telnet_line_supports_ipv6_and_rejects_missing_endpoints() -> None:
    fields = selected_telnet_fields(set(TELNET_REQUIRED_FIELDS) | {"ipv6.src", "ipv6.dst"})
    values = _values()
    values.pop("ip.src")
    values.pop("ip.dst")
    values.update({"ipv6.src": "2001:db8::2", "ipv6.dst": "2001:db8::1"})

    assert parse_telnet_line(_row(values, fields), fields).source == "2001:db8::2"
    values.pop("ipv6.src")
    with pytest.raises(ValueError, match="source or destination"):
        parse_telnet_line(_row(values, fields), fields)


def test_tshark_telnet_arguments_are_bounded_structured_fields() -> None:
    available = set(TELNET_REQUIRED_FIELDS) | {"ip.src", "ip.dst"}
    arguments = tshark_telnet_arguments(
        Path("tshark"), Path("capture.pcap"), available_fields=available
    )

    assert "telnet" in arguments
    assert "telnet.data" in arguments
    assert "tcp.payload" not in arguments
    assert "ipv6.src" not in arguments
