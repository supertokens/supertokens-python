from typing import Any, Dict, List, cast
from unittest.mock import AsyncMock, MagicMock

import pytest
from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.querier import Querier
from supertokens_python.recipe.passwordless.recipe_implementation import (
    RecipeImplementation,
)
from supertokens_python.recipe.passwordless.types import DeviceType

SELECTORS = [
    ("list_codes_by_device_id", "deviceId", "device-id", False),
    ("list_codes_by_pre_auth_session_id", "preAuthSessionId", "pre-auth-id", False),
    ("list_codes_by_email", "email", "test@example.com", True),
    ("list_codes_by_phone_number", "phoneNumber", "+12025550123", True),
]


def make_device(code_count: int) -> Dict[str, Any]:
    return {
        "preAuthSessionId": "pre-auth-id",
        "failedCodeInputAttemptCount": 2,
        "email": "test@example.com",
        "phoneNumber": "+12025550123",
        "codes": [
            {
                "codeId": f"code-{index}",
                "timeCreated": 1700000000000 + index,
                "codeLifetime": 900000 + index,
            }
            for index in range(code_count)
        ],
    }


@pytest.mark.parametrize("method,query_key,value,returns_list", SELECTORS)
@pytest.mark.parametrize("code_count", [0, 1, 2])
async def test_list_codes_preserves_codes_and_device_metadata(
    method: str, query_key: str, value: str, returns_list: bool, code_count: int
):
    device = make_device(code_count)
    querier = MagicMock(spec=Querier)
    querier.send_get_request = AsyncMock(
        return_value={"status": "OK", "devices": [device]}
    )
    recipe = RecipeImplementation(cast(Querier, querier))
    context: Dict[str, Any] = {"test": "context"}

    result = await getattr(recipe, method)(value, "tenant-a", context)

    if returns_list:
        assert len(result) == 1
        actual = cast(DeviceType, result[0])
    else:
        assert result is not None
        actual = cast(DeviceType, result)
    assert actual.pre_auth_session_id == device["preAuthSessionId"]
    assert actual.failed_code_input_attempt_count == 2
    assert actual.email == device["email"]
    assert actual.phone_number == device["phoneNumber"]
    assert [
        (code.code_id, code.time_created, code.code_life_time) for code in actual.codes
    ] == [
        (code["codeId"], code["timeCreated"], code["codeLifetime"])
        for code in device["codes"]
    ]
    querier.send_get_request.assert_awaited_once()
    args, kwargs = querier.send_get_request.call_args
    assert (
        args[0].get_as_string_dangerous()
        == NormalisedURLPath("tenant-a/recipe/signinup/codes").get_as_string_dangerous()
    )
    assert args[1] == {query_key: value}
    assert kwargs == {"user_context": context}


@pytest.mark.parametrize("method,query_key,value,returns_list", SELECTORS)
async def test_list_codes_without_codes_or_contact_fields(
    method: str, query_key: str, value: str, returns_list: bool
):
    device = make_device(0)
    for field in ("codes", "email", "phoneNumber"):
        del device[field]
    querier = MagicMock(spec=Querier)
    querier.send_get_request = AsyncMock(return_value={"devices": [device]})
    recipe = RecipeImplementation(cast(Querier, querier))

    result = await getattr(recipe, method)(value, "public", {})

    actual = cast(DeviceType, result[0] if returns_list else result)
    assert actual.codes == []
    assert actual.email is None
    assert actual.phone_number is None


@pytest.mark.parametrize("method,query_key,value,returns_list", SELECTORS)
@pytest.mark.parametrize("response", [{"devices": []}, {}])
async def test_list_codes_without_devices(
    method: str,
    query_key: str,
    value: str,
    returns_list: bool,
    response: Dict[str, Any],
):
    querier = MagicMock(spec=Querier)
    querier.send_get_request = AsyncMock(return_value=response)
    recipe = RecipeImplementation(cast(Querier, querier))

    result = await getattr(recipe, method)(value, "public", {})

    assert result == ([] if returns_list else None)


@pytest.mark.parametrize("method,query_key,value,returns_list", SELECTORS)
async def test_list_codes_with_multiple_devices(
    method: str, query_key: str, value: str, returns_list: bool
):
    first, second = make_device(1), make_device(2)
    second["preAuthSessionId"] = "another-pre-auth-id"
    querier = MagicMock(spec=Querier)
    querier.send_get_request = AsyncMock(return_value={"devices": [first, second]})
    recipe = RecipeImplementation(cast(Querier, querier))

    result = await getattr(recipe, method)(value, "public", {})

    if returns_list:
        devices = cast(List[DeviceType], result)
        assert [device.pre_auth_session_id for device in devices] == [
            "pre-auth-id",
            "another-pre-auth-id",
        ]
        assert [[code.code_id for code in device.codes] for device in devices] == [
            ["code-0"],
            ["code-0", "code-1"],
        ]
    else:
        assert result is None
