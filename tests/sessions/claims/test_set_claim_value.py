import time
from unittest.mock import patch, MagicMock

from pytest import mark

from supertokens_python import init
from supertokens_python.framework import BaseRequest
from supertokens_python.recipe.session.asyncio import (
    create_new_session,
    get_session_information,
    set_claim_value,
)
from supertokens_python.recipe.session.session_class import Session
from tests.sessions.claims.utils import TrueClaim, st_init_args_with_TrueClaim
from tests.utils import setup_function, teardown_function
from tests.utils import start_st, AsyncMock

_ = setup_function  # type:ignore
_ = teardown_function  # type:ignore

pytestmark = (
    mark.asyncio
)  # no need to apply @mark.asyncio on each test because of this!

timestamp = time.time()


async def test_should_merge_the_right_value():
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
        await session.set_claim_value(TrueClaim, "NEW_TRUE")
        ((update, _), _) = mock.call_args_list[0]
        assert update["st-true"]["t"] > 0
        update["st-true"]["t"] = 0
        mock.assert_called_once_with({"st-true": {"t": 0, "v": "NEW_TRUE"}}, None)


async def test_should_overwrite_claim_value():
    init(**st_init_args_with_TrueClaim)  # type: ignore
    start_st()

    dummy_req: BaseRequest = MagicMock()
    s = await create_new_session(dummy_req, "someId")

    payload = s.get_access_token_payload()
    assert payload["st-true"]["t"] > 0
    payload["st-true"]["t"] = timestamp
    assert payload == {"st-true": {"t": timestamp, "v": True}}

    await s.set_claim_value(TrueClaim, "NEW_TRUE")

    # Payload should be updated now:
    payload = s.get_access_token_payload()
    assert payload["st-true"]["t"] > 0
    payload["st-true"]["t"] = timestamp
    assert payload == {"st-true": {"t": timestamp, "v": "NEW_TRUE"}}


async def test_should_overwrite_claim_value_using_session_handle():
    init(**st_init_args_with_TrueClaim)  # type: ignore
    start_st()

    dummy_req: BaseRequest = MagicMock()
    s = await create_new_session(dummy_req, "someId")

    payload = s.get_access_token_payload()
    assert payload["st-true"]["t"] > 0
    payload["st-true"]["t"] = timestamp
    assert payload == {"st-true": {"t": timestamp, "v": True}}

    await set_claim_value(s.get_handle(), TrueClaim, "NEW_TRUE")

    # Payload should be updated now:
    # Note that the session var (s) still contains the old payload.
    # We need to fetch the new one.
    s = await get_session_information(s.get_handle())
    assert s is not None
    payload = s.access_token_payload
    assert payload["st-true"]["t"] > 0
    payload["st-true"]["t"] = timestamp
    assert payload == {"st-true": {"t": timestamp, "v": "NEW_TRUE"}}


async def test_should_work_ok_for_non_existing_handles():
    init(**st_init_args_with_TrueClaim)  # type: ignore
    start_st()

    res = await set_claim_value("non-existing-handle", TrueClaim, "NEW_TRUE")
    assert res is False
