from unittest.mock import MagicMock, patch

from pytest import mark

from supertokens_python import init
from supertokens_python.framework import BaseRequest
from supertokens_python.recipe.session import SessionContainer
from supertokens_python.recipe.session.asyncio import (
    create_new_session,
    get_session_information,
    remove_claim,
)
from supertokens_python.recipe.session.session_class import Session
from tests.sessions.claims.utils import TrueClaim, get_st_init_args
from tests.utils import AsyncMock, setup_function, start_st, teardown_function

_ = setup_function  # type:ignore
_ = teardown_function  # type:ignore

pytestmark = mark.asyncio


async def test_should_attempt_to_set_claim_to_none():
    recipe_implementation_mock = AsyncMock()
    session_config_mock = MagicMock()

    result = MagicMock()
    result.access_token = None
    recipe_implementation_mock.regenerate_access_token.return_value = result  # type: ignore

    user_session = Session(
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
        wraps=user_session.merge_into_access_token_payload,
    ) as mock:
        await user_session.remove_claim(TrueClaim)
        mock.assert_called_once_with({"st-true": None}, {})


async def test_should_clear_previously_set_claim(timestamp: int):
    init(**get_st_init_args(TrueClaim))  # type:ignore
    start_st()

    dummy_req: BaseRequest = MagicMock()
    s: SessionContainer = await create_new_session(dummy_req, "public", "someId")

    payload = s.get_access_token_payload()

    assert payload["st-true"] == {"v": True, "t": timestamp}


async def test_should_clear_previously_set_claim_using_handle(timestamp: int):
    init(**get_st_init_args(TrueClaim))  # type:ignore
    start_st()

    dummy_req: BaseRequest = MagicMock()
    s: SessionContainer = await create_new_session(dummy_req, "public", "someId")

    payload = s.get_access_token_payload()
    assert payload["st-true"] == {"v": True, "t": timestamp}

    res = await remove_claim(s.get_handle(), TrueClaim)
    assert res is True

    session_info = await get_session_information(s.get_handle())
    assert session_info is not None
    payload_after = session_info.custom_claims_in_access_token_payload
    assert (
        payload_after.pop("iss", None) is not None
    )  # checks that iss is present & not None and then removes it
    assert payload_after == {}


async def test_should_work_ok_for_non_existing_handle():
    init(**get_st_init_args(TrueClaim))  # type:ignore
    start_st()

    res = await remove_claim("non-existing-handle", TrueClaim)
    assert res is False
