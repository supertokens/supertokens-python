import time as real_time
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

from pytest import mark
from supertokens_python.recipe.session.claims import PrimitiveClaim

timestamp = real_time.time()
val = {"foo": 1}
SECONDS = 1_000


def _test_wrapper(fn: Any) -> Any:
    time_patcher = patch(
        "supertokens_python.recipe.session.claim_base_classes.primitive_claim.time",
        wraps=real_time,
    )
    return time_patcher(mark.asyncio(fn))  # type: ignore


sync_fetch_value = MagicMock(return_value=val)
async_fetch_value = AsyncMock(return_value=val)


def teardown_function(_):
    sync_fetch_value.reset_mock()
    async_fetch_value.reset_mock()


@_test_wrapper
async def test_primitive_claim(time_mock: MagicMock):
    time_mock.time.return_value = timestamp  # type: ignore

    claim = PrimitiveClaim("key", sync_fetch_value)
    ctx = {}
    res = await claim.build("user_id", ctx)
    assert res == {"key": {"t": timestamp, "v": val}}


@_test_wrapper
async def test_primitive_claim_without_async_fetch_value(time_mock: MagicMock):
    time_mock.time.return_value = timestamp  # type: ignore

    claim = PrimitiveClaim("key", async_fetch_value)
    ctx = {}
    res = await claim.build("user_id", ctx)
    assert res == {"key": {"t": timestamp, "v": val}}


@_test_wrapper
async def test_primitive_claim_matching__add_to_payload(time_mock: MagicMock):
    time_mock.time.return_value = timestamp  # type: ignore

    claim = PrimitiveClaim("key", sync_fetch_value)
    ctx = {}
    res = await claim.build("user_id", ctx)
    assert res == claim.add_to_payload_({}, val, {})


@_test_wrapper
async def test_primitive_claim_fetch_value_params_correct(time_mock: MagicMock):
    time_mock.time.return_value = timestamp  # type: ignore

    claim = PrimitiveClaim("key", sync_fetch_value)
    user_id, ctx = "user_id", {}
    await claim.build(user_id, ctx)
    assert sync_fetch_value.call_count == 1
    assert (user_id, ctx) == sync_fetch_value.call_args_list[0].args


@_test_wrapper
async def test_primitive_claim_fetch_value_none(time_mock: MagicMock):
    time_mock.time.return_value = timestamp  # type: ignore

    fetch_value_none = MagicMock()
    fetch_value_none.return_value = None

    claim = PrimitiveClaim("key", fetch_value_none)
    user_id, ctx = "user_id", {}
    res = await claim.build(user_id, ctx)
    assert res == {}


# Get value from payload:


@_test_wrapper
async def test_get_value_from_empty_payload(time_mock: MagicMock):
    time_mock.time.return_value = timestamp  # type: ignore

    claim = PrimitiveClaim("key", sync_fetch_value)
    assert claim.get_value_from_payload({}) is None


@_test_wrapper
async def test_should_return_value_set_by__add_to_payload_internal(
    time_mock: MagicMock,
):
    time_mock.time.return_value = timestamp  # type: ignore

    claim = PrimitiveClaim("key", sync_fetch_value)
    payload = claim.add_to_payload_({}, val)
    assert claim.get_value_from_payload(payload) == val


# Get last refetch time:

val2 = {"bar": 2}


@_test_wrapper
async def test_get_last_refetch_time_empty_payload(time_mock: MagicMock):
    time_mock.time.return_value = timestamp  # type: ignore

    claim = PrimitiveClaim("key", async_fetch_value)
    assert claim.get_last_refetch_time({}) is None


@_test_wrapper
async def test_should_return_none_for_empty_payload(time_mock: MagicMock):
    time_mock.time.return_value = timestamp  # type: ignore

    claim = PrimitiveClaim("key", sync_fetch_value)
    payload = await claim.build("user_id")

    assert claim.get_last_refetch_time(payload) == timestamp


# validators.has_value


@_test_wrapper
async def test_validators_should_not_validate_empty_payload(_time_mock: MagicMock):
    claim = PrimitiveClaim("key", sync_fetch_value)
    res = claim.validators.has_value(val).validate({})  # TODO: missing await

    assert res == {
        "isValid": False,
        "reason": {
            "expectedValue": val,
            "actualValue": None,
            "message": "wrong value",
        },
    }


@_test_wrapper
async def test_should_not_validate_mismatching_payload(_time_mock: MagicMock):
    claim = PrimitiveClaim("key", sync_fetch_value)
    payload = await claim.build("user_id")
    res = claim.validators.has_value(val2).validate(payload)

    assert res == {
        "isValid": False,
        "reason": {
            "expectedValue": val2,
            "actualValue": val,
            "message": "wrong value",
        },
    }


@_test_wrapper
async def test_validator_should_validate_matching_payload(_time_mock: MagicMock):
    claim = PrimitiveClaim("key", sync_fetch_value)
    payload = await claim.build("user_id")
    res = claim.validators.has_value(val).validate(payload)

    assert res == {"isValid": True}


@_test_wrapper
async def test_should_validate_old_values_as_well(time_mock: MagicMock):
    time_mock.time.return_value = timestamp  # type: ignore

    claim = PrimitiveClaim("key", sync_fetch_value)
    payload = await claim.build("user_id")

    # Increase clock time by 1000
    time_mock.time.return_value += 100 * SECONDS  # type: ignore

    res = claim.validators.has_value(val).validate(payload)
    assert res == {"isValid": True}


@_test_wrapper
async def test_should_refetch_if_value_not_set(_time_mock: MagicMock):
    claim = PrimitiveClaim("key", sync_fetch_value)
    assert claim.validators.has_value(val).should_refetch(val2, {}) is True


@_test_wrapper
async def test_validator_should_not_refetch_if_value_is_set(_time_mock: MagicMock):
    claim = PrimitiveClaim("key", sync_fetch_value)
    payload = await claim.build("user_id")
    assert claim.validators.has_value(val2).should_refetch(payload, {}) is False


# validators.has_fresh_value


@_test_wrapper
async def test_should_not_validate_empty_payload(_time_mock: MagicMock):
    claim = PrimitiveClaim("key", sync_fetch_value)
    res = claim.validators.has_fresh_value(val, 600).validate({}, {})
    assert res == {
        "isValid": False,
        "reason": {
            "expectedValue": val,
            "actualValue": None,
            "message": "wrong value",
        },
    }


@_test_wrapper
async def test_has_fresh_value_should_not_validate_mismatching_payload(
    _time_mock: MagicMock,
):
    claim = PrimitiveClaim("key", sync_fetch_value)
    payload = await claim.build("user_id")
    res = claim.validators.has_fresh_value(val2, 600).validate(payload)
    assert res == {
        "isValid": False,
        "reason": {
            "expectedValue": val2,
            "actualValue": val,
            "message": "wrong value",
        },
    }


@_test_wrapper
async def test_should_validate_matching_payload(_time_mock: MagicMock):
    claim = PrimitiveClaim("key", sync_fetch_value)
    payload = await claim.build("user_id")
    res = claim.validators.has_fresh_value(val, 600).validate(payload)
    assert res == {"isValid": True}


@_test_wrapper
async def test_should_not_validate_old_values_as_well(time_mock: MagicMock):
    time_mock.time.return_value = timestamp  # type: ignore

    claim = PrimitiveClaim("key", sync_fetch_value)
    payload = await claim.build("user_id")

    # Increase clock time:
    time_mock.time.return_value += 100 * SECONDS  # type: ignore

    res = claim.validators.has_fresh_value(val, 10).validate(payload)
    assert res == {
        "isValid": False,
        "reason": {
            "ageInSeconds": 100,
            "maxAgeInSeconds": 10,
            "message": "expired",
        },
    }


@_test_wrapper
async def test_should_refetch_if_value_is_not_set(_time_mock: MagicMock):
    claim = PrimitiveClaim("key", sync_fetch_value)

    assert claim.validators.has_fresh_value(val2, 600).should_refetch({}) is True


@_test_wrapper
async def test_should_not_refetch_if_value_is_set(_time_mock: MagicMock):
    claim = PrimitiveClaim("key", sync_fetch_value)
    payload = await claim.build("userId")

    assert claim.validators.has_fresh_value(val2, 600).should_refetch(payload) is False


@_test_wrapper
async def test_should_refetch_if_value_is_old(time_mock: MagicMock):
    # TODO: FIXME
    time_mock.time.return_value = timestamp  # type: ignore

    claim = PrimitiveClaim("key", sync_fetch_value)
    payload = await claim.build("userId")

    # Increase clock time:
    time_mock.time.return_value += 100 * SECONDS  # type: ignore

    assert claim.validators.has_fresh_value(val2, 10).should_refetch(payload) is True
