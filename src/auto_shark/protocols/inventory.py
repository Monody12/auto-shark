"""Structured, payload-free TShark capture inventory rows."""

from __future__ import annotations

import csv
from dataclasses import dataclass
from io import StringIO
from typing import Optional

INVENTORY_FIELDS = (
    "frame.number",
    "frame.time_epoch",
    "frame.len",
    "frame.cap_len",
    "frame.protocols",
    "ip.src",
    "ipv6.src",
    "ip.dst",
    "ipv6.dst",
    "tcp.stream",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.len",
    "tcp.flags.syn",
    "tcp.flags.ack",
    "udp.stream",
    "udp.srcport",
    "udp.dstport",
    "udp.length",
)

INVENTORY_REQUIRED_FIELDS = frozenset(
    {
        "frame.number",
        "frame.time_epoch",
        "frame.len",
        "frame.cap_len",
        "frame.protocols",
    }
)


def _int(value: str) -> Optional[int]:
    return int(value) if value else None


def _bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true"}


@dataclass(frozen=True)
class InventoryRow:
    frame_number: int
    time_epoch: str
    frame_length: int
    captured_length: int
    protocols: tuple[str, ...]
    source: Optional[str]
    destination: Optional[str]
    transport: Optional[str]
    stream_index: Optional[int]
    source_port: Optional[int]
    destination_port: Optional[int]
    payload_length: Optional[int]
    syn: bool
    ack: bool


def selected_inventory_fields(available_fields: set[str]) -> tuple[str, ...]:
    return tuple(
        field
        for field in INVENTORY_FIELDS
        if field in INVENTORY_REQUIRED_FIELDS or field in available_fields
    )


def parse_inventory_line(
    line: bytes, fields: tuple[str, ...] = INVENTORY_FIELDS
) -> InventoryRow:
    rows = list(
        csv.reader(
            StringIO(line.decode("utf-8", errors="strict")),
            delimiter="\t",
            quotechar='"',
        )
    )
    if len(rows) != 1:
        raise ValueError("inventory line must contain one tabular row")
    values = rows[0]
    if len(values) != len(fields):
        raise ValueError(f"expected {len(fields)} inventory columns, received {len(values)}")
    data = dict(zip(fields, values))
    source = data.get("ip.src") or data.get("ipv6.src") or None
    destination = data.get("ip.dst") or data.get("ipv6.dst") or None
    tcp_stream = _int(data.get("tcp.stream", ""))
    udp_stream = _int(data.get("udp.stream", ""))
    transport = "tcp" if tcp_stream is not None else "udp" if udp_stream is not None else None
    stream_index = tcp_stream if tcp_stream is not None else udp_stream
    if transport == "tcp":
        source_port = _int(data.get("tcp.srcport", ""))
        destination_port = _int(data.get("tcp.dstport", ""))
        payload_length = _int(data.get("tcp.len", ""))
    elif transport == "udp":
        source_port = _int(data.get("udp.srcport", ""))
        destination_port = _int(data.get("udp.dstport", ""))
        udp_length = _int(data.get("udp.length", ""))
        payload_length = max(udp_length - 8, 0) if udp_length is not None else None
    else:
        source_port = destination_port = payload_length = None
    protocols = tuple(item for item in data.get("frame.protocols", "").split(":") if item)
    return InventoryRow(
        frame_number=int(data["frame.number"]),
        time_epoch=data.get("frame.time_epoch", ""),
        frame_length=int(data["frame.len"]),
        captured_length=int(data["frame.cap_len"]),
        protocols=protocols,
        source=source,
        destination=destination,
        transport=transport,
        stream_index=stream_index,
        source_port=source_port,
        destination_port=destination_port,
        payload_length=payload_length,
        syn=_bool(data.get("tcp.flags.syn", "")),
        ack=_bool(data.get("tcp.flags.ack", "")),
    )


def tshark_inventory_arguments(
    executable: str, capture: str, fields: tuple[str, ...] = INVENTORY_FIELDS
) -> list[str]:
    arguments = [
        executable, "-r", capture, "-T", "fields", "-E", "separator=/t", "-E", "quote=d",
        "-E", "escape=y",
    ]
    for field in fields:
        arguments.extend(("-e", field))
    return arguments
