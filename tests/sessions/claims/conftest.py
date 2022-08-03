from pytest import fixture
from supertokens_python.utils import get_timestamp_ms
from pytest_mock.plugin import MockerFixture
from typing import Tuple


@fixture()
def primitive_claim_time_patch(mocker: MockerFixture):
    timestamp = get_timestamp_ms()
    patched_get_timestamp_ms = mocker.patch(
        "supertokens_python.recipe.session.claim_base_classes.primitive_claim.get_timestamp_ms"
    )
    patched_get_timestamp_ms.return_value = timestamp

    return patched_get_timestamp_ms, timestamp


@fixture()
def timestamp(primitive_claim_time_patch: Tuple[MockerFixture, int]):
    return primitive_claim_time_patch[1]


@fixture()
def patch_get_timestamp_ms(primitive_claim_time_patch: Tuple[MockerFixture, int]):
    return primitive_claim_time_patch[0]
