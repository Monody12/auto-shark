from pathlib import Path

import pytest

from auto_shark.protocols.http import HTTP_FIELDS, parse_http_line, tshark_http_arguments


def _row(values: dict[str, str]) -> bytes:
    columns = [f'"{values.get(field, "")}"' for field in HTTP_FIELDS]
    return "\t".join(columns).encode()


def test_parse_http_request() -> None:
    message = parse_http_line(
        _row(
            {
                "frame.number": "180",
                "frame.time_epoch": "1512733290.736582912",
                "frame.len": "729",
                "frame.cap_len": "729",
                "tcp.stream": "1",
                "ip.src": "192.0.2.1",
                "ip.dst": "192.0.2.2",
                "tcp.srcport": "47844",
                "tcp.dstport": "80",
                "http.request.method": "POST",
                "http.request.uri": "/upload/1.php",
                "http.response_in": "183",
                "http.content_length": "675",
            }
        )
    )
    assert message.kind == "request"
    assert message.frame_number == 180
    assert message.response_in_frame == 183
    assert message.uri == "/upload/1.php"


def test_parse_http_response_uses_ipv6_fallback() -> None:
    message = parse_http_line(
        _row(
            {
                "frame.number": "183",
                "frame.time_epoch": "1.0",
                "frame.len": "399",
                "frame.cap_len": "399",
                "tcp.stream": "1",
                "ipv6.src": "2001:db8::2",
                "ipv6.dst": "2001:db8::1",
                "tcp.srcport": "80",
                "tcp.dstport": "47844",
                "http.response.code": "200",
                "http.response.phrase": "OK",
                "http.request_in": "180",
            }
        )
    )
    assert message.kind == "response"
    assert message.source == "2001:db8::2"
    assert message.request_in_frame == 180


def test_parse_http_line_rejects_wrong_column_count() -> None:
    with pytest.raises(ValueError, match="columns"):
        parse_http_line(b'"1"\t"2"')


def test_tshark_filter_excludes_udp_ssdp_requests() -> None:
    arguments = tshark_http_arguments(Path("tshark"), Path("capture.pcap"))
    assert "tcp && (http.request || http.response)" in arguments
