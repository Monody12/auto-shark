from auto_shark.protocols.inventory import (
    INVENTORY_FIELDS,
    parse_inventory_line,
    selected_inventory_fields,
    tshark_inventory_arguments,
)


def _line(values: dict[str, str], fields: tuple[str, ...] = INVENTORY_FIELDS) -> bytes:
    return "\t".join(values.get(field, "") for field in fields).encode()


def test_parse_tcp_ipv4_inventory_row_without_payload_hex() -> None:
    row = parse_inventory_line(
        _line(
            {
                "frame.number": "4",
                "frame.time_epoch": "1.25",
                "frame.len": "74",
                "frame.cap_len": "74",
                "frame.protocols": "eth:ethertype:ip:tcp:telnet",
                "ip.src": "10.0.0.1",
                "ip.dst": "10.0.0.2",
                "tcp.stream": "3",
                "tcp.srcport": "1234",
                "tcp.dstport": "23",
                "tcp.len": "20",
                "tcp.flags.syn": "1",
                "tcp.flags.ack": "0",
            }
        )
    )
    assert row.transport == "tcp"
    assert row.stream_index == 3
    assert row.payload_length == 20
    assert row.syn and not row.ack
    assert row.protocols[-1] == "telnet"


def test_parse_udp_ipv6_inventory_row_never_assigns_roles() -> None:
    row = parse_inventory_line(
        _line(
            {
                "frame.number": "9",
                "frame.time_epoch": "2.5",
                "frame.len": "80",
                "frame.cap_len": "78",
                "frame.protocols": "eth:ethertype:ipv6:udp:dns",
                "ipv6.src": "2001:db8::1",
                "ipv6.dst": "2001:db8::2",
                "udp.stream": "7",
                "udp.srcport": "53000",
                "udp.dstport": "53",
                "udp.length": "28",
            }
        )
    )
    assert row.transport == "udp"
    assert row.payload_length == 20
    assert not row.syn and not row.ack


def test_inventory_arguments_use_only_selected_fields() -> None:
    selected = selected_inventory_fields(set(INVENTORY_FIELDS) - {"ipv6.src", "ipv6.dst"})
    arguments = tshark_inventory_arguments("tshark", "capture.pcap", selected)
    assert "tcp.payload" not in arguments
    assert "ipv6.src" not in arguments
    assert arguments.count("-e") == len(selected)
