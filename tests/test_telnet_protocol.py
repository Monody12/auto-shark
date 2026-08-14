import pytest

from auto_shark.protocols.telnet import TelnetParser, parse_telnet_chunks


def _ranges(records):
    return [(item.kind, item.start, item.end, item.command, item.option) for item in records]


def test_parser_preserves_application_and_split_command_ranges() -> None:
    records = parse_telnet_chunks([b"Password: ", b"\xff", b"\xf2", b"^C"])

    assert _ranges(records) == [
        ("application", 0, 10, None, None),
        ("command", 10, 12, 242, None),
        ("application", 12, 14, None, None),
    ]
    assert sum(item.byte_length for item in records) == 14


def test_parser_handles_negotiation_subnegotiation_and_escaped_iac() -> None:
    payload = b"A\xff\xfb\x01B\xff\xfa\x18X\xff\xffY\xff\xf0C\xff\xffD"
    records = parse_telnet_chunks([payload[:2], payload[2:8], payload[8:13], payload[13:]])

    assert _ranges(records) == [
        ("application", 0, 1, None, None),
        ("negotiation", 1, 4, 251, 1),
        ("application", 4, 5, None, None),
        ("subnegotiation", 5, 14, 250, 24),
        ("application", 14, 15, None, None),
        ("application", 15, 17, None, None),
        ("application", 17, 18, None, None),
    ]
    assert sum(item.byte_length for item in records) == len(payload)


@pytest.mark.parametrize(
    ("payload", "command"),
    [(b"\xff", None), (b"\xff\xfb", 251), (b"\xff\xfa\x18abc", 24)],
)
def test_parser_marks_incomplete_control_tail(payload, command) -> None:
    records = parse_telnet_chunks([payload])

    assert _ranges(records) == [("incomplete-control", 0, len(payload), command, None)]


def test_parser_keeps_cr_nul_and_binary_application_bytes() -> None:
    payload = b"line\r\x00\n\x00\x80"
    parser = TelnetParser()
    assert parser.feed(payload[:3]) == ()
    assert parser.feed(payload[3:]) == ()
    records = parser.finish()

    assert _ranges(records) == [("application", 0, len(payload), None, None)]
    assert parser.offset == len(payload)
    assert parser.finish() == ()
    with pytest.raises(ValueError, match="finished"):
        parser.feed(b"later")
