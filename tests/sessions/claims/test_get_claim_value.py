from unittest.mock import MagicMock

from pytest import mark

from supertokens_python import init
from supertokens_python.framework.request import BaseRequest
from supertokens_python.recipe import session
from supertokens_python.recipe.session.asyncio import (
    create_new_session,
    get_claim_value,
)
from supertokens_python.recipe.session.interfaces import (
    SessionContainer,
    GetClaimValueOkResult,
    SessionDoesNotExistError,
)
from tests.utils import setup_function, teardown_function, start_st, st_init_common_args
from .utils import TrueClaim, get_st_init_args

_ = setup_function  # type:ignore
_ = teardown_function  # type:ignore

pytestmark = mark.asyncio


async def test_should_get_the_right_value():
    init(**get_st_init_args(TrueClaim))  # type:ignore
    start_st()

    dummy_req: BaseRequest = MagicMock()
    s = await create_new_session(dummy_req, "someId")

    res = await s.get_claim_value(TrueClaim)
    assert res is True


async def test_should_get_the_right_value_using_session_handle():
    init(**get_st_init_args(TrueClaim))  # type:ignore
    start_st()

    dummy_req: BaseRequest = MagicMock()
    s: SessionContainer = await create_new_session(dummy_req, "someId")

    res = await get_claim_value(s.get_handle(), TrueClaim)
    assert isinstance(res, GetClaimValueOkResult)
    assert res.value is True


async def test_should_work_for_non_existing_handle():
    new_st_init = {**st_init_common_args, "recipe_list": [session.init()]}
    init(**new_st_init)  # type: ignore
    start_st()

    res = await get_claim_value("non_existing_handle", TrueClaim)
    assert isinstance(res, SessionDoesNotExistError)
