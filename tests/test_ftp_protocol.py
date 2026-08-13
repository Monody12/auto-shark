from pathlib import Path

import pytest

from auto_shark.protocols.ftp import (
    FTP_FIELDS,
    FTP_REQUIRED_FIELDS,
    parse_ftp_line,
    selected_ftp_fields,
    tshark_ftp_arguments,
)


def _row(values: dict[str, str], fields: tuple[str, ...] = FTP_FIELDS) -> bytes:
    return "\t".join(f'"{values.get(field, "")}"' for field in fields).encode()


def _base() -> dict[str, str]:
    return {
        "frame.number": "55",
        "frame.time_epoch": "1438585167.027246000",
        "frame.len": "218",
        "frame.cap_len": "218",
        "tcp.stream": "4",
        "ip.src": "172.16.66.10",
        "ip.dst": "172.16.66.188",
        "tcp.srcport": "14438",
        "tcp.dstport": "51801",
        "tcp.len": "164",
    }


def test_parse_ftp_data_uses_explicit_frame_references() -> None:
    values = _base()
    values.update(
        {
            "ftp-data.setup-frame": "44",
            "ftp-data.setup-method": "PASV",
            "ftp-data.command-frame": "49",
            "ftp-data.command": "RETR flag.rar",
        }
    )

    packet = parse_ftp_line(_row(values))

    assert packet.kind == "data"
    assert packet.setup_frame == 44
    assert packet.command_frame == 49
    assert packet.payload_length == 164
    assert packet.direction == "172.16.66.10:14438>172.16.66.188:51801"


def test_parse_ftp_response_uses_ipv6_fallback() -> None:
    fields = selected_ftp_fields(set(FTP_REQUIRED_FIELDS) | {"ipv6.src", "ipv6.dst"})
    values = _base()
    values.pop("ip.src")
    values.pop("ip.dst")
    values.update(
        {
            "ipv6.src": "2001:db8::1",
            "ipv6.dst": "2001:db8::2",
            "ftp.response.code": "227",
            "ftp.response.arg": "Entering Passive Mode",
            "ftp.passive.ip": "192.0.2.1",
            "ftp.passive.port": "14438",
        }
    )

    packet = parse_ftp_line(_row(values, fields), fields)

    assert packet.kind == "response"
    assert packet.source == "2001:db8::1"
    assert packet.response_code == 227
    assert packet.passive_port == 14438


def test_parse_ftp_rejects_wrong_columns_and_untyped_row() -> None:
    with pytest.raises(ValueError, match="columns"):
        parse_ftp_line(b'"1"\t"2"')
    with pytest.raises(ValueError, match="neither"):
        parse_ftp_line(_row(_base()))


def test_tshark_ftp_arguments_are_structured_and_capability_selected() -> None:
    available = set(FTP_REQUIRED_FIELDS) | {"ip.src", "ip.dst"}
    arguments = tshark_ftp_arguments(
        Path("tshark"), Path("capture.pcap"), available_fields=available
    )
    assert "ftp || ftp-data" in arguments
    assert "ftp-data.command-frame" in arguments
    assert "ipv6.src" not in arguments
