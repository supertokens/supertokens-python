from unittest.mock import MagicMock, patch

from pytest import mark

from supertokens_python import init
from supertokens_python.framework import BaseRequest
from supertokens_python.recipe.session.asyncio import (
    create_new_session,
    get_session_information,
    set_claim_value,
)
from supertokens_python.recipe.session.session_class import Session
from tests.sessions.claims.utils import TrueClaim, get_st_init_args
from tests.utils import AsyncMock, setup_function, start_st, teardown_function

_ = setup_function  # type:ignore
_ = teardown_function  # type:ignore

pytestmark = (
    mark.asyncio
)  # no need to apply @mark.asyncio on each test because of this!


async def test_should_merge_the_right_value(timestamp: int):
    recipe_implementation_mock = AsyncMock()
    session_config_mock = MagicMock()

    result = MagicMock()
    result.access_token = None
    recipe_implementation_mock.regenerate_access_token.return_value = result  # type: ignore

    session = Session(
        recipe_implementation_mock,
        session_config_mock,
        "test_access_token",
        "test_front_token",
        None,  # refresh token
        None,  # anti csrf token
        "test_session_handle",
        "test_user_id",
        {},  # user_data_in_access_token
        None,  # req_res_info
        False,  # access_token_updated
        "public",
    )
    with patch.object(
        Session,
        "merge_into_access_token_payload",
        wraps=session.merge_into_access_token_payload,
    ) as mock:
        await session.set_claim_value(TrueClaim, False)
        mock.assert_called_once_with({"st-true": {"t": timestamp, "v": False}}, {})


async def test_should_overwrite_claim_value(timestamp: int):
    init(**get_st_init_args(TrueClaim))  # type: ignore
    start_st()

    dummy_req: BaseRequest = MagicMock()
    s = await create_new_session(dummy_req, "public", "someId")

    payload = s.get_access_token_payload()
    assert len(payload) == 10
    assert payload["st-true"] == {"t": timestamp, "v": True}

    await s.set_claim_value(TrueClaim, False)

    # Payload should be updated now:
    payload = s.get_access_token_payload()
    assert len(payload) == 10
    assert payload["st-true"] == {"t": timestamp, "v": False}


async def test_should_overwrite_claim_value_using_session_handle(timestamp: int):
    init(**get_st_init_args(TrueClaim))  # type: ignore
    start_st()

    dummy_req: BaseRequest = MagicMock()
    s = await create_new_session(dummy_req, "public", "someId")

    payload = s.get_access_token_payload()
    assert len(payload) == 10
    assert payload["st-true"] == {"t": timestamp, "v": True}

    await set_claim_value(s.get_handle(), TrueClaim, False)

    # Check after update:
    s = await get_session_information(s.get_handle())
    assert s is not None
    payload = s.custom_claims_in_access_token_payload
    assert payload.pop("iss", None) is not None  # checks iss as well as removes it
    assert payload == {"st-true": {"t": timestamp, "v": False}}


async def test_should_work_ok_for_non_existing_handles():
    init(**get_st_init_args(TrueClaim))  # type: ignore
    start_st()

    res = await set_claim_value("non-existing-handle", TrueClaim, False)
    assert res is False
