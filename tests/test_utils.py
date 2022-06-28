import pytest
from supertokens_python.utils import humanize_time, is_version_gte


@pytest.mark.parametrize(
    "version,min_minor_version,is_gte",
    [
        (
            "1.12",
            "1.12",
            True,
        ),
        (
            "1.12.0",
            "1.12",
            True,
        ),
        (
            "2.12.0",
            "1.12",
            True,
        ),
        (
            "1.13",
            "1.12",
            True,
        ),
        (
            "1.13.0",
            "1.12",
            True,
        ),
        (
            "0.11.0",
            "1.12",
            False,
        ),
        (
            "1.11.0",
            "1.11",
            True,
        ),
    ],
)
def test_util_is_version_gte(version: str, min_minor_version: str, is_gte: bool):
    assert is_version_gte(version, min_minor_version) == is_gte


@pytest.mark.parametrize(
    "version,base_version",
    [
        ("1.12.0", "1.12.0"),
        ("1.12.0", "1.12.0.1"),
        ("1.12.0", "1.0.0"),
        ("1.12.0", "1"),
    ],
)
def test_utils_is_version_gte_raises_error_if_not_minimum_minor_version(
    version: str, base_version: str
):
    with pytest.raises(AssertionError):
        is_version_gte(version, base_version)


SECOND = 1000
MINUTE = 60 * SECOND
HOUR = 60 * MINUTE


@pytest.mark.parametrize(
    "ms,out",
    [
        (1 * SECOND, "1 second"),
        (59 * SECOND, "59 seconds"),
        (1 * MINUTE, "1 minute"),
        ((1 * MINUTE + 59 * SECOND), "1 minute"),
        (2 * MINUTE, "2 minutes"),
        (1 * HOUR, "1 hour"),
        ((1 * HOUR + 1 * MINUTE), "1 hour"),
        ((1 * HOUR + 6 * MINUTE), "1.1 hours"),
        ((2 * HOUR + 1 * MINUTE), "2 hours"),
        (5 * HOUR, "5 hours"),
    ],
)
def test_humanize_time(ms: int, out: str):
    assert humanize_time(ms) == out
