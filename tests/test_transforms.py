

def test_decode_recognized_handles_zlib_and_gzip() -> None:
    import zlib

    from auto_shark.transforms.recognize import decode_recognized

    payload = b"flag{compressed-layer-ok}"
    zlibbed = zlib.compress(payload)
    result = decode_recognized(zlibbed, max_output_bytes=1024)
    assert result is not None and result.transform == "zlib"
    assert result.output == payload

    gzipbed = zlib.compress(payload, wbits=16 + zlib.MAX_WBITS)
    result = decode_recognized(gzipbed, max_output_bytes=1024)
    assert result is not None and result.transform == "gzip"
    assert result.output == payload

    # Over-budget decompression is refused, not truncated.
    big = zlib.compress(b"A" * 4096)
    assert decode_recognized(big, max_output_bytes=64) is None
    # Non-compressed values still route through the base64/hex recognizers.
    assert decode_recognized(b"ZmxhZ3tlaH0=", max_output_bytes=64).transform == "base64"
