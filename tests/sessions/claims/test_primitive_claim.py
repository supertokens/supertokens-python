from unittest.mock import MagicMock

from pytest import mark
from supertokens_python.recipe.session.claims import PrimitiveClaim
from supertokens_python.utils import resolve
from tests.utils import AsyncMock

from supertokens_python.recipe.multitenancy.constants import DEFAULT_TENANT_ID

val = {"foo": 1}
SECONDS = 1_000
MINS = 60 * SECONDS

sync_fetch_value = MagicMock(return_value=val)
async_fetch_value = AsyncMock(return_value=val)

pytestmark = mark.asyncio


def teardown_function(_):
    sync_fetch_value.reset_mock()
    async_fetch_value.reset_mock()


async def test_primitive_claim(timestamp: int):
    claim = PrimitiveClaim("key", sync_fetch_value)
    ctx = {}
    res = await claim.build("user_id", "public", ctx)
    assert res == {"key": {"t": timestamp, "v": val}}


async def test_primitive_claim_without_async_fetch_value(timestamp: int):
    claim = PrimitiveClaim("key", async_fetch_value)
    ctx = {}
    res = await claim.build("user_id", "public", ctx)
    assert res == {"key": {"t": timestamp, "v": val}}


async def test_primitive_claim_matching__add_to_payload():
    claim = PrimitiveClaim("key", sync_fetch_value)
    ctx = {}
    res = await claim.build("user_id", "public", ctx)
    assert res == claim.add_to_payload_({}, val, {})


async def test_primitive_claim_fetch_value_params_correct():
    claim = PrimitiveClaim("key", sync_fetch_value)
    user_id, ctx = "user_id", {}
    await claim.build(user_id, DEFAULT_TENANT_ID, ctx)
    assert sync_fetch_value.call_count == 1
    assert (user_id, DEFAULT_TENANT_ID, ctx) == sync_fetch_value.call_args_list[0][
        0
    ]  # extra [0] refers to call params


async def test_primitive_claim_fetch_value_none():
    fetch_value_none = MagicMock()
    fetch_value_none.return_value = None

    claim = PrimitiveClaim("key", fetch_value_none)
    user_id, ctx = "user_id", {}
    res = await claim.build(user_id, DEFAULT_TENANT_ID, ctx)
    assert res == {}


# Get value from payload:


async def test_get_value_from_empty_payload():
    claim = PrimitiveClaim("key", sync_fetch_value)
    assert claim.get_value_from_payload({}) is None


async def test_should_return_value_set_by__add_to_payload_internal():
    claim = PrimitiveClaim("key", sync_fetch_value)
    payload = claim.add_to_payload_({}, val)
    assert claim.get_value_from_payload(payload) == val


# Get last refetch time:

val2 = {"bar": 2}


async def test_get_last_refetch_time_empty_payload():
    claim = PrimitiveClaim("key", async_fetch_value)
    assert claim.get_last_refetch_time({}) is None


async def test_should_return_none_for_empty_payload(timestamp: int):
    claim = PrimitiveClaim("key", sync_fetch_value)
    payload = await claim.build("user_id", DEFAULT_TENANT_ID)

    assert claim.get_last_refetch_time(payload) == timestamp


# validators.has_value


async def test_validators_should_not_validate_empty_payload():
    claim = PrimitiveClaim("key", sync_fetch_value)
    res = await claim.validators.has_value(val).validate({}, {})

    assert res.is_valid is False
    assert res.reason == {
        "expectedValue": val,
        "actualValue": None,
        "message": "value does not exist",
    }


async def test_should_not_validate_mismatching_payload():
    claim = PrimitiveClaim("key", sync_fetch_value)
    payload = await claim.build("user_id", DEFAULT_TENANT_ID)
    res = await claim.validators.has_value(val2).validate(payload, {})

    assert res.is_valid is False
    assert res.reason == {
        "expectedValue": val2,
        "actualValue": val,
        "message": "wrong value",
    }


async def test_validator_should_validate_matching_payload():
    claim = PrimitiveClaim("key", sync_fetch_value)
    payload = await claim.build("user_id", DEFAULT_TENANT_ID)
    res = await claim.validators.has_value(val).validate(payload, {})

    assert res.is_valid is True


async def test_should_validate_old_values_as_well(patch_get_timestamp_ms: MagicMock):
    claim = PrimitiveClaim("key", sync_fetch_value)
    payload = await claim.build("user_id", DEFAULT_TENANT_ID)

    # Increase clock time by 10 mins:
    patch_get_timestamp_ms.return_value += 10 * MINS  # type: ignore

    res = await claim.validators.has_value(val).validate(payload, {})
    assert res.is_valid is True


async def test_should_refetch_if_value_not_set():
    claim = PrimitiveClaim("key", async_fetch_value)
    assert (
        await resolve(claim.validators.has_value(val).should_refetch(val2, {})) is True
    )


async def test_validator_should_not_refetch_if_value_is_set():
    claim = PrimitiveClaim("key", sync_fetch_value)
    payload = await claim.build("user_id", DEFAULT_TENANT_ID)
    assert (
        await resolve(claim.validators.has_value(val2).should_refetch(payload, {}))
        is False
    )


# validators.has_fresh_value


async def test_should_not_validate_empty_payload():
    claim = PrimitiveClaim("key", sync_fetch_value)
    res = await claim.validators.has_value(val, 600).validate({}, {})
    assert res.is_valid is False
    assert res.reason == {
        "expectedValue": val,
        "actualValue": None,
        "message": "value does not exist",  # TODO: Validate that this is actually correct.
        # because this makes sense yet the node PR isn't aligned with this.
    }


async def test_has_fresh_value_should_not_validate_mismatching_payload():
    claim = PrimitiveClaim("key", sync_fetch_value)
    payload = await claim.build("user_id", DEFAULT_TENANT_ID)
    res = await claim.validators.has_value(val2, 600).validate(payload, {})
    assert res.is_valid is False
    assert res.reason == {
        "expectedValue": val2,
        "actualValue": val,
        "message": "wrong value",
    }


async def test_should_validate_matching_payload():
    claim = PrimitiveClaim("key", sync_fetch_value)
    payload = await claim.build("user_id", DEFAULT_TENANT_ID)
    res = await claim.validators.has_value(val, 600).validate(payload, {})
    assert res.is_valid is True


async def test_should_not_validate_old_values_as_well(
    patch_get_timestamp_ms: MagicMock,
):

    claim = PrimitiveClaim("key", sync_fetch_value)
    payload = await claim.build("user_id", DEFAULT_TENANT_ID)

    # Increase clock time by 10 mins:
    patch_get_timestamp_ms.return_value += 10 * MINS  # type: ignore

    res = await claim.validators.has_value(val).validate(payload, {})
    assert res.is_valid is True


async def test_should_refetch_if_value_is_not_set():
    claim = PrimitiveClaim("key", sync_fetch_value)

    assert claim.validators.has_value(val2, 600).should_refetch({}, {}) is True


async def test_should_not_refetch_if_value_is_set():
    claim = PrimitiveClaim("key", sync_fetch_value)
    payload = await claim.build("userId", "public")

    assert claim.validators.has_value(val2, 600).should_refetch(payload, {}) is False


async def test_should_refetch_if_value_is_old(patch_get_timestamp_ms: MagicMock):
    claim = PrimitiveClaim("key", sync_fetch_value)
    payload = await claim.build("userId", DEFAULT_TENANT_ID)

    # Increase clock time by 10 mins:
    patch_get_timestamp_ms.return_value += 10 * MINS  # type: ignore

    assert claim.validators.has_value(val2).should_refetch(payload, {}) is False


async def test_should_not_validate_old_values_as_well_with_default_max_age_provided(
    patch_get_timestamp_ms: MagicMock,
):
    claim = PrimitiveClaim("key", sync_fetch_value, 300)  # 5 mins
    payload = await claim.build("user_id", DEFAULT_TENANT_ID)

    # Increase clock time by 10 mins:
    patch_get_timestamp_ms.return_value += 10 * MINS  # type: ignore

    res = await claim.validators.has_value(val).validate(payload, {})
    assert res.is_valid is False
    assert res.reason == {
        "ageInSeconds": 600,
        "maxAgeInSeconds": 300,
        "message": "expired",
    }


async def test_should_refetch_if_value_is_old_with_default_max_age_provided(
    patch_get_timestamp_ms: MagicMock,
):
    claim = PrimitiveClaim("key", sync_fetch_value, 300)  # 5 mins
    payload = await claim.build("userId", "public")

    # Increase clock time by 10 mins:
    patch_get_timestamp_ms.return_value += 10 * MINS  # type: ignore

    assert claim.validators.has_value(val2).should_refetch(payload, {}) is True
