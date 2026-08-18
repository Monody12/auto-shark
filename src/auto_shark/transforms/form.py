"""Byte-accurate application/x-www-form-urlencoded parsing."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import unquote_to_bytes


@dataclass(frozen=True)
class FormFieldValue:
    ordinal: int
    name: str
    raw_name_offset: int
    raw_name_length: int
    raw_name: bytes
    raw_offset: int
    raw_length: int
    raw_value: bytes
    decoded_value: bytes


def _url_decode(value: bytes) -> bytes:
    return unquote_to_bytes(value.replace(b"+", b" "))


def parse_urlencoded_form(data: bytes, *, max_fields: int = 1024) -> list[FormFieldValue]:
    """Parse an ordered form while retaining each raw value's byte range."""
    if max_fields <= 0:
        raise ValueError("max_fields must be positive")
    fields: list[FormFieldValue] = []
    cursor = 0
    for ordinal, part in enumerate(data.split(b"&")):
        if ordinal >= max_fields:
            raise ValueError("URL form exceeds the configured field limit")
        separator = part.find(b"=")
        if separator < 0:
            raw_name, raw_value = part, b""
            value_offset = cursor + len(part)
        else:
            raw_name, raw_value = part[:separator], part[separator + 1 :]
            value_offset = cursor + separator + 1
        decoded_name = _url_decode(raw_name).decode("utf-8", errors="replace")
        fields.append(
            FormFieldValue(
                ordinal=ordinal,
                name=decoded_name,
                raw_name_offset=cursor,
                raw_name_length=len(raw_name),
                raw_name=raw_name,
                raw_offset=value_offset,
                raw_length=len(raw_value),
                raw_value=raw_value,
                decoded_value=_url_decode(raw_value),
            )
        )
        cursor += len(part) + 1
    return fields
