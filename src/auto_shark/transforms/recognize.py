"""Conservative recognition of common CTF encodings."""

from __future__ import annotations

import base64
import binascii
import re
import zlib
from dataclasses import dataclass
from typing import Optional

_BASE64 = re.compile(rb"[A-Za-z0-9+/]*={0,2}")
_BASE64URL = re.compile(rb"[A-Za-z0-9_-]*={0,2}")
_HEX = re.compile(rb"[0-9A-Fa-f]+")
_WHITESPACE = re.compile(rb"\s+")
_ZLIB_SECOND_BYTES = frozenset((0x01, 0x5E, 0x9C, 0xDA))


@dataclass(frozen=True)
class DecodedValue:
    transform: str
    version: str
    output: bytes
    parameters: dict[str, object]


def _padding(value: bytes) -> bytes:
    return value + b"=" * ((-len(value)) % 4)


def _decompress_bounded(stripped: bytes, max_output_bytes: int) -> Optional[tuple[str, bytes]]:
    """Decompress gzip/zlib data (the layer after base64 in WebShell chains)."""

    if len(stripped) < 2:
        return None
    try:
        if stripped[0] == 0x1F and stripped[1] == 0x8B:
            decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
            name = "gzip"
        elif stripped[0] == 0x78 and stripped[1] in _ZLIB_SECOND_BYTES:
            decompressor = zlib.decompressobj()
            name = "zlib"
        else:
            return None
        output = decompressor.decompress(stripped, max_output_bytes + 1)
        if decompressor.unconsumed_tail or len(output) > max_output_bytes:
            return None
        if not output:
            return None
        return name, output
    except zlib.error:
        return None


def decode_recognized(value: bytes, *, max_output_bytes: int) -> Optional[DecodedValue]:
    """Decode one high-confidence Base64/Base64URL/hex/gzip/zlib value, or None."""
    if max_output_bytes <= 0:
        raise ValueError("max output bytes must be positive")
    stripped = value.strip()
    if len(stripped) >= 8:
        decompressed = _decompress_bounded(stripped, max_output_bytes)
        if decompressed is not None:
            name, output = decompressed
            return DecodedValue(
                transform=name,
                version="1",
                output=output,
                parameters={"input_length": len(stripped)},
            )
    compacted = _WHITESPACE.sub(b"", stripped)
    whitespace_removed = compacted != stripped
    if len(compacted) >= 8 and len(compacted) % 2 == 0 and _HEX.fullmatch(compacted):
        output_length = len(compacted) // 2
        if output_length > max_output_bytes:
            return None
        return DecodedValue(
            transform="hex",
            version="1",
            output=bytes.fromhex(compacted.decode("ascii")),
            parameters={
                "input_length": len(compacted),
                "whitespace_removed": whitespace_removed,
            },
        )
    if len(compacted) < 8:
        return None
    decoder = None
    name = ""
    if _BASE64.fullmatch(compacted) and (
        b"+" in compacted or b"/" in compacted or b"=" in compacted
    ):
        decoder = base64.b64decode
        name = "base64"
    elif _BASE64URL.fullmatch(compacted) and (b"-" in compacted or b"_" in compacted):
        decoder = base64.urlsafe_b64decode
        name = "base64url"
    elif _BASE64.fullmatch(compacted) and len(compacted) % 4 == 0:
        decoder = base64.b64decode
        name = "base64"
    if decoder is None:
        return None
    try:
        output = decoder(_padding(compacted))
    except (binascii.Error, ValueError):
        return None
    if not output or len(output) > max_output_bytes:
        return None
    return DecodedValue(
        transform=name,
        version="1",
        output=output,
        parameters={
            "input_length": len(compacted),
            "padding_inferred": len(compacted) % 4 != 0,
            "whitespace_removed": whitespace_removed,
        },
    )
