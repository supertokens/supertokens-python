import pytest

from tests.utils import reset


def pytest_configure():
    import os

    os.environ.setdefault("SUPERTOKENS_ENV", "testing")
    os.environ.setdefault("SUPERTOKENS_PATH", "../supertokens-root")
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.Django.settings")


@pytest.fixture(autouse=True)
def setup_teardown():
    """
    Common setup/teardown for all tests.
    Runs per-test.
    """

    # Setup
    reset()

    # Yield to test function
    yield

    # Teardown
    reset()
