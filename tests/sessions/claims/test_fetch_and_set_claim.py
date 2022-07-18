import time
from unittest.mock import AsyncMock, patch

from pytest import mark

from supertokens_python.recipe.session.session_class import Session
from tests.sessions.claims.utils import NoneClaim, TrueClaim

timestamp = time.time()

pytestmark = (
    mark.asyncio
)  # no need to apply @mark.asyncio on each test because of this!


async def test_should_not_change_if_claim_fetch_value_returns_none():
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
        await session.fetch_and_set_claim(NoneClaim)
        mock.assert_called_once_with({}, None)


async def test_should_update_if_claim_fetch_value_returns_value():
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
        await session.fetch_and_set_claim(TrueClaim)
        update, _ = mock.call_args_list[0].args
        assert update["st-true"]["t"] > 0
        update["st-true"]["t"] = timestamp
        mock.assert_called_once_with({"st-true": {"t": timestamp, "v": True}}, None)
