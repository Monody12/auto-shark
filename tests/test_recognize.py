import base64

from auto_shark.transforms.recognize import decode_recognized


def test_recognizes_base64_and_hex() -> None:
    original = b"D:\\www\\flag.jpg"
    encoded = base64.b64encode(original)
    assert decode_recognized(encoded, max_output_bytes=100).output == original
    assert decode_recognized(b"ffd8ffe000104a46", max_output_bytes=100).output.startswith(
        b"\xff\xd8"
    )


def test_rejects_ambiguous_short_or_oversized_values() -> None:
    assert decode_recognized(b"abcd", max_output_bytes=100) is None
    assert decode_recognized(b"414243444546", max_output_bytes=2) is None


def test_decode_recognized_strips_internal_whitespace_for_base64_and_hex() -> None:
    jpeg = b"\xff\xd8\xff\xe0\x00\x10JFIF" + b"\x00" * 8
    encoded = base64.b64encode(jpeg)
    wrapped = b"\r\n".join(encoded[i : i + 16] for i in range(0, len(encoded), 16))
    result = decode_recognized(wrapped, max_output_bytes=1000)
    assert result is not None
    assert result.transform == "base64"
    assert result.output.startswith(b"\xff\xd8\xff")
    assert result.parameters["whitespace_removed"] is True

    hexed = decode_recognized(b"ff d8 ff e0", max_output_bytes=100)
    assert hexed is not None and hexed.transform == "hex"
    assert hexed.output == bytes.fromhex("ffd8ffe0")
    assert hexed.parameters["whitespace_removed"] is True

    assert decode_recognized(b"<html>ZmxhZ3tlaH0=</html>", max_output_bytes=100) is None
