import hashlib
from io import BytesIO

from auto_shark.storage.blobs import BlobStore


def test_blob_store_is_content_addressed_and_idempotent(tmp_path) -> None:
    data = b"packet evidence\x00" * 100
    store = BlobStore(tmp_path / "blobs")
    first = store.put_stream(BytesIO(data), chunk_size=17)
    second = store.put_bytes(data)
    assert first == second
    assert first.sha256 == hashlib.sha256(data).hexdigest()
    assert first.byte_length == len(data)
    assert first.path.read_bytes() == data
    assert first.path.parts[-3:-1] == ("sha256", first.sha256[:2])
