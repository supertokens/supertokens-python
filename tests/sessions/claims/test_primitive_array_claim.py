import math
from typing import List, Tuple
from unittest.mock import MagicMock

from pytest import fixture, mark
from pytest_mock import MockerFixture
from supertokens_python.recipe.session.claims import PrimitiveArrayClaim
from supertokens_python.utils import get_timestamp_ms, resolve
from tests.utils import AsyncMock

val = ["a"]
included_item = "a"
excluded_item = "b"

SECONDS = 1_000
MINS = 60 * SECONDS

sync_fetch_value = MagicMock(return_value=val)
async_fetch_value = AsyncMock(return_value=val)

claim_with_inf_max_age: PrimitiveArrayClaim[List[str]] = PrimitiveArrayClaim(
    "key",
    sync_fetch_value,
    math.inf,  # type: ignore
)

pytestmark = mark.asyncio


def teardown_function(_):
    sync_fetch_value.reset_mock()
    async_fetch_value.reset_mock()


@fixture()
def pac_time_patch(mocker: MockerFixture):
    """Patches get_timestamp_ms function of PrimitiveArrayClaim"""
    timestamp = get_timestamp_ms()
    patched_get_timestamp_ms = mocker.patch(
        "supertokens_python.recipe.session.claim_base_classes.primitive_array_claim.get_timestamp_ms"
    )
    patched_get_timestamp_ms.return_value = timestamp

    return patched_get_timestamp_ms, timestamp


@fixture()
def timestamp(pac_time_patch: Tuple[MockerFixture, int]):
    return pac_time_patch[1]


@fixture()
def patch_get_timestamp_ms(pac_time_patch: Tuple[MockerFixture, int]):
    return pac_time_patch[0]


async def test_primitive_claim(timestamp: int):
    claim = PrimitiveArrayClaim("key", sync_fetch_value)
    ctx = {}
    res = await claim.build("user_id", ctx)
    assert res == {"key": {"t": timestamp, "v": val}}


async def test_primitive_claim_without_async_fetch_value(timestamp: int):
    claim = PrimitiveArrayClaim("key", async_fetch_value)
    ctx = {}
    res = await claim.build("user_id", ctx)
    assert res == {"key": {"t": timestamp, "v": val}}


async def test_primitive_claim_matching__add_to_payload():
    claim = PrimitiveArrayClaim("key", sync_fetch_value)
    ctx = {}
    res = await claim.build("user_id", ctx)
    assert res == claim.add_to_payload_({}, val, {})


async def test_primitive_claim_fetch_value_params_correct():
    claim = PrimitiveArrayClaim("key", sync_fetch_value)
    user_id, ctx = "user_id", {}
    await claim.build(user_id, ctx)
    assert sync_fetch_value.call_count == 1
    assert (user_id, ctx) == sync_fetch_value.call_args_list[0][
        0
    ]  # extra [0] refers to call params


async def test_primitive_claim_fetch_value_none():
    fetch_value_none = MagicMock()
    fetch_value_none.return_value = None

    claim = PrimitiveArrayClaim("key", fetch_value_none)
    user_id, ctx = "user_id", {}
    res = await claim.build(user_id, ctx)
    assert res == {}


# Get value from payload:


async def test_get_value_from_empty_payload():
    claim = PrimitiveArrayClaim("key", sync_fetch_value)
    assert claim.get_value_from_payload({}) is None


async def test_should_return_value_set_by__add_to_payload_internal():
    claim = PrimitiveArrayClaim("key", sync_fetch_value)
    payload = claim.add_to_payload_({}, val)
    assert claim.get_value_from_payload(payload) == val


# Get last refetch time:


async def test_get_last_refetch_time_empty_payload():
    claim = PrimitiveArrayClaim("key", async_fetch_value)
    assert claim.get_last_refetch_time({}) is None


async def test_should_return_none_for_empty_payload(timestamp: int):
    claim = PrimitiveArrayClaim("key", sync_fetch_value)
    payload = await claim.build("user_id")

    assert claim.get_last_refetch_time(payload) == timestamp


# validators.includes


async def test_validators_should_not_validate_empty_payload():
    claim = PrimitiveArrayClaim("key", sync_fetch_value)
    res = await claim.validators.includes(included_item).validate({}, {})

    assert res.is_valid is False
    assert res.reason == {
        "expectedToInclude": included_item,
        "actualValue": None,
        "message": "value does not exist",
    }


async def test_should_not_validate_mismatching_payload():
    claim = PrimitiveArrayClaim("key", sync_fetch_value)
    payload = await claim.build("user_id")
    res = await claim.validators.includes(excluded_item).validate(payload, {})

    assert res.is_valid is False
    assert res.reason == {
        "expectedToInclude": excluded_item,
        "actualValue": val,
        "message": "wrong value",
    }


async def test_validator_should_validate_matching_payload():
    claim = PrimitiveArrayClaim("key", sync_fetch_value)
    payload = await claim.build("user_id")
    res = await claim.validators.includes(included_item).validate(payload, {})

    assert res.is_valid is True


async def test_should_not_validate_old_values(patch_get_timestamp_ms: MagicMock):
    claim = claim_with_inf_max_age
    payload = await claim.build("user_id")

    # Increase clock time by 1 week
    patch_get_timestamp_ms.return_value += 7 * 24 * 60 * 60 * SECONDS  # type: ignore

    res = await claim.validators.includes(included_item, 600).validate(payload, {})
    assert res.is_valid is False
    assert res.reason == {
        "ageInSeconds": 604800.0,
        "maxAgeInSeconds": 600,
        "message": "expired",
    }


async def test_should_validate_old_values_if_max_age_is_none_and_default_is_inf(
    patch_get_timestamp_ms: MagicMock,
):
    claim = claim_with_inf_max_age
    payload = await claim.build("user_id")

    # Increase clock time by 1 week
    patch_get_timestamp_ms.return_value += 7 * 24 * 60 * 60 * SECONDS  # type: ignore

    res = await claim.validators.includes(included_item).validate(payload, {})
    assert res.is_valid is True


async def test_should_refetch_if_value_not_set():
    claim = claim_with_inf_max_age
    assert await resolve(
        claim.validators.includes(excluded_item, 600).should_refetch({}, {}) is True
    )


async def test_validator_should_not_refetch_if_value_is_set():
    claim = claim_with_inf_max_age
    payload = await claim.build("user_id")
    assert (
        await resolve(
            claim.validators.includes(excluded_item, 600).should_refetch(payload, {})
        )
        is False
    )


async def test_validator_should_refetch_if_value_is_old(
    patch_get_timestamp_ms: MagicMock,
):
    claim = claim_with_inf_max_age
    payload = await claim.build("user_id")

    # Increase clock time by 1 week
    patch_get_timestamp_ms.return_value += 7 * 24 * 60 * 60 * SECONDS  # type: ignore

    assert (
        await resolve(
            claim.validators.includes(excluded_item, 600).should_refetch(payload, {})
        )
        is True
    )


async def test_validator_should_not_refetch_if_max_age_is_none_and_default_is_inf(
    patch_get_timestamp_ms: MagicMock,
):
    claim = claim_with_inf_max_age
    payload = await claim.build("user_id")

    # Increase clock time by 1 week
    patch_get_timestamp_ms.return_value += 7 * 24 * 60 * 60 * SECONDS  # type: ignore

    assert (
        await resolve(
            claim.validators.includes(excluded_item).should_refetch(payload, {})
        )
        is False
    )


async def test_validator_should_validate_values_with_default_max_age(
    patch_get_timestamp_ms: MagicMock,
):
    claim = PrimitiveArrayClaim("key", sync_fetch_value)
    payload = await claim.build("user_id")

    # Increase clock time by 10 MINS:
    patch_get_timestamp_ms.return_value += 10 * MINS  # type: ignore

    res = await resolve(claim.validators.includes(included_item).validate(payload, {}))
    assert res.is_valid is True


async def test_validator_should_not_refetch_if_max_age_overrides_to_inf(
    patch_get_timestamp_ms: MagicMock,
):
    claim = PrimitiveArrayClaim("key", sync_fetch_value)
    payload = await claim.build("user_id")

    # Increase clock time by 1 week
    patch_get_timestamp_ms.return_value += 7 * 24 * 60 * 60 * SECONDS  # type: ignore

    assert (
        await resolve(
            claim.validators.includes(
                included_item,
                math.inf,  # type:ignore
            ).should_refetch(payload, {})
        )
        is False
    )


# validator.excludes:


async def test_validator_excludes_should_not_validate_empty_payload():
    claim = PrimitiveArrayClaim("key", sync_fetch_value)
    res = await claim.validators.excludes(excluded_item).validate({}, {})

    assert res.is_valid is False
    assert res.reason == {
        "expectedToNotInclude": excluded_item,
        "actualValue": None,
        "message": "value does not exist",
    }


async def test_validator_excludes_should_not_validate_mismatching_payload():
    claim = PrimitiveArrayClaim("key", sync_fetch_value)
    payload = await claim.build("user_id")
    res = await claim.validators.excludes(included_item).validate(payload, {})

    assert res.is_valid is False
    assert res.reason == {
        "expectedToNotInclude": included_item,
        "actualValue": val,
        "message": "wrong value",
    }


async def test_validator_excludes_should_validate_matching_payload():
    claim = PrimitiveArrayClaim("key", sync_fetch_value)
    payload = await claim.build("user_id")
    res = await claim.validators.excludes(excluded_item).validate(payload, {})

    assert res.is_valid is True


# validator.includes_all:


async def test_validator_includes_all_should_not_validate_empty_payload():
    claim = PrimitiveArrayClaim("key", sync_fetch_value)
    res = await claim.validators.includes_all(included_item).validate({}, {})

    assert res.is_valid is False
    assert res.reason == {
        "expectedToInclude": included_item,
        "actualValue": None,
        "message": "value does not exist",
    }


async def test_validator_includes_all_should_not_validate_mismatching_payload():
    claim = PrimitiveArrayClaim("key", sync_fetch_value)
    payload = await claim.build("user_id")
    res = await claim.validators.includes_all(excluded_item).validate(payload, {})

    assert res.is_valid is False
    assert res.reason == {
        "expectedToInclude": excluded_item,
        "actualValue": val,
        "message": "wrong value",
    }


async def test_validator_includes_all_should_validate_matching_payload():
    claim = PrimitiveArrayClaim("key", sync_fetch_value)
    payload = await claim.build("user_id")
    res = await claim.validators.includes_all(included_item).validate(payload, {})

    assert res.is_valid is True


# validator.excludes_all:


async def test_validator_excludes_all_should_not_validate_empty_payload():
    claim = PrimitiveArrayClaim("key", sync_fetch_value)
    res = await claim.validators.excludes_all(excluded_item).validate({}, {})

    assert res.is_valid is False
    assert res.reason == {
        "expectedToNotInclude": excluded_item,
        "actualValue": None,
        "message": "value does not exist",
    }


async def test_validator_excludes_all_should_not_validate_mismatching_payload():
    claim = PrimitiveArrayClaim("key", sync_fetch_value)
    payload = await claim.build("user_id")
    res = await claim.validators.excludes_all(included_item).validate(payload, {})

    assert res.is_valid is False
    assert res.reason == {
        "expectedToNotInclude": included_item,
        "actualValue": val,
        "message": "wrong value",
    }


async def test_validator_excludes_all_should_validate_matching_payload():
    claim = PrimitiveArrayClaim("key", sync_fetch_value)
    payload = await claim.build("user_id")
    res = await claim.validators.excludes_all(excluded_item).validate(payload, {})

    assert res.is_valid is True


async def test_validator_should_not_validate_older_values_with_5min_default_max_age(
    patch_get_timestamp_ms: MagicMock,
):
    claim = PrimitiveArrayClaim("key", sync_fetch_value, 300)  # 5 mins
    payload = await claim.build("user_id")

    # Increase clock time by 10 MINS:
    patch_get_timestamp_ms.return_value += 10 * MINS  # type: ignore

    res = await resolve(claim.validators.includes(included_item).validate(payload, {}))
    assert res.is_valid is False
    assert res.reason == {
        "ageInSeconds": 600,
        "maxAgeInSeconds": 300,
        "message": "expired",
    }
