import pytest

from auto_shark.body import _classify_body


@pytest.mark.parametrize(
    ("declared", "actual", "truncated", "expected"),
    [
        (10, 10, False, "complete"),
        (None, 10, False, "complete"),
        (0, 0, False, "empty"),
        (None, 0, False, "absent"),
        (10, 0, False, "missing"),
        (10, 5, False, "partial"),
        (5, 10, False, "length-mismatch"),
        (10, 5, True, "limit-truncated"),
    ],
)
def test_body_status_classification(declared, actual, truncated, expected) -> None:
    assert _classify_body(declared, actual, truncated) == expected
