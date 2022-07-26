import time as real_time
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
from tests.sessions.claims.utils import TrueClaim
from tests.utils import setup_function, start_st, teardown_function

from .test_get_claim_value import st_init_args_with_TrueClaim
from .utils import time_patch_wrapper
from tests.utils import AsyncMock

_ = setup_function  # type:ignore
_ = teardown_function  # type:ignore

timestamp = real_time.time()


@mark.asyncio
async def test_should_attempt_to_set_claim_to_none():
    recipe_implementation_mock = AsyncMock()
    session = Session(
        recipe_implementation_mock,
        "test_access_token",
        "test_session_handle",
        "test_user_id",
        {},
    )
    with patch.object(
        Session,
        "merge_into_access_token_payload",
        wraps=session.merge_into_access_token_payload,
    ) as mock:
        await session.remove_claim(TrueClaim)
        mock.assert_called_once_with({"st-true": None}, {})


@time_patch_wrapper
async def test_should_clear_previously_set_claim(time_mock: MagicMock):
    time_mock.time.return_value = timestamp  # type: ignore
    init(**st_init_args_with_TrueClaim)  # type:ignore
    start_st()

    dummy_req: BaseRequest = MagicMock()
    s: SessionContainer = await create_new_session(dummy_req, "someId")

    payload = s.get_access_token_payload()

    assert payload == {"st-true": {"v": True, "t": timestamp}}


@time_patch_wrapper
async def test_should_clear_previously_set_claim_using_handle(time_mock: MagicMock):
    time_mock.time.return_value = timestamp  # type: ignore
    init(**st_init_args_with_TrueClaim)  # type:ignore
    start_st()

    dummy_req: BaseRequest = MagicMock()
    s: SessionContainer = await create_new_session(dummy_req, "someId")

    payload = s.get_access_token_payload()
    assert payload == {"st-true": {"v": True, "t": timestamp}}

    res = await remove_claim(s.get_handle(), TrueClaim)
    assert res is True

    session_info = await get_session_information(s.get_handle())
    assert session_info is not None
    payload_after = session_info.access_token_payload
    assert payload_after == {}


@time_patch_wrapper
async def test_should_work_ok_for_non_existing_handle(_time_mock: MagicMock):
    init(**st_init_args_with_TrueClaim)  # type:ignore
    start_st()

    res = await remove_claim("non-existing-handle", TrueClaim)
    assert res is False
