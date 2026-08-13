"""Structured TShark TCP segment adapter."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

TCP_REQUIRED_FIELDS = (
    "frame.number",
    "frame.time_epoch",
    "frame.cap_len",
    "frame.len",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.stream",
    "tcp.seq",
    "tcp.seq_raw",
    "tcp.len",
    "tcp.payload",
)

TCP_OPTIONAL_FIELDS = (
    "ip.src",
    "ipv6.src",
    "ip.dst",
    "ipv6.dst",
    "tcp.flags.syn",
    "tcp.flags.fin",
    "tcp.flags.reset",
    "tcp.analysis.retransmission",
    "tcp.analysis.spurious_retransmission",
    "tcp.analysis.out_of_order",
    "tcp.analysis.lost_segment",
)

TCP_FIELDS = TCP_REQUIRED_FIELDS + TCP_OPTIONAL_FIELDS


@dataclass(frozen=True)
class TcpPacket:
    frame_number: int
    time_epoch: str
    captured_length: int
    frame_length: int
    source: str
    source_port: int
    destination: str
    destination_port: int
    stream_index: int
    sequence_relative: int
    sequence_raw: int
    payload: bytes
    syn: bool
    fin: bool
    reset: bool
    retransmission: bool
    spurious_retransmission: bool
    out_of_order: bool
    lost_segment: bool

    @property
    def direction(self) -> str:
        return f"{self.source}:{self.source_port}>{self.destination}:{self.destination_port}"


def _integer(value: str, field: str) -> int:
    try:
        return int(value)
    except ValueError as error:
        raise ValueError(f"invalid {field}: {value!r}") from error


def selected_tcp_fields(available_fields: set[str]) -> tuple[str, ...]:
    return tuple(
        field for field in TCP_FIELDS if field in TCP_REQUIRED_FIELDS or field in available_fields
    )


def parse_tcp_line(line: bytes, fields: Optional[tuple[str, ...]] = None) -> TcpPacket:
    selected = TCP_FIELDS if fields is None else fields
    values = line.decode("utf-8").split("\t")
    values.extend([""] * (len(selected) - len(values)))
    if len(values) != len(selected):
        raise ValueError(f"expected {len(selected)} TCP fields, got {len(values)}")
    field_values = dict(zip(selected, values))
    source = field_values.get("ip.src", "") or field_values.get("ipv6.src", "")
    destination = field_values.get("ip.dst", "") or field_values.get("ipv6.dst", "")
    if not source or not destination:
        raise ValueError("TCP packet is missing IP endpoints")
    payload_text = field_values["tcp.payload"].replace(":", "")
    try:
        payload = bytes.fromhex(payload_text) if payload_text else b""
    except ValueError as error:
        raise ValueError("invalid hexadecimal TCP payload") from error
    declared_length = _integer(field_values["tcp.len"] or "0", "tcp.len")
    if len(payload) != declared_length:
        raise ValueError(
            f"TCP payload length mismatch: field={declared_length}, decoded={len(payload)}"
        )
    return TcpPacket(
        frame_number=_integer(field_values["frame.number"], "frame.number"),
        time_epoch=field_values["frame.time_epoch"],
        captured_length=_integer(field_values["frame.cap_len"], "frame.cap_len"),
        frame_length=_integer(field_values["frame.len"], "frame.len"),
        source=source,
        source_port=_integer(field_values["tcp.srcport"], "tcp.srcport"),
        destination=destination,
        destination_port=_integer(field_values["tcp.dstport"], "tcp.dstport"),
        stream_index=_integer(field_values["tcp.stream"], "tcp.stream"),
        sequence_relative=_integer(field_values["tcp.seq"], "tcp.seq"),
        sequence_raw=_integer(field_values["tcp.seq_raw"], "tcp.seq_raw"),
        payload=payload,
        syn=bool(field_values.get("tcp.flags.syn", "")),
        fin=bool(field_values.get("tcp.flags.fin", "")),
        reset=bool(field_values.get("tcp.flags.reset", "")),
        retransmission=bool(field_values.get("tcp.analysis.retransmission", "")),
        spurious_retransmission=bool(field_values.get("tcp.analysis.spurious_retransmission", "")),
        out_of_order=bool(field_values.get("tcp.analysis.out_of_order", "")),
        lost_segment=bool(field_values.get("tcp.analysis.lost_segment", "")),
    )


def tshark_tcp_arguments(
    executable: Path,
    capture: Path,
    stream_index: int,
    *,
    available_fields: set[str],
) -> list[str]:
    if stream_index < 0:
        raise ValueError("TCP stream index cannot be negative")
    arguments = [
        str(executable),
        "-r",
        str(capture),
        "-Y",
        f"tcp.stream == {stream_index}",
        "-T",
        "fields",
        "-E",
        "separator=/t",
        "-E",
        "occurrence=f",
    ]
    selected_fields = selected_tcp_fields(available_fields)
    for field in selected_fields:
        arguments.extend(("-e", field))
    return arguments
