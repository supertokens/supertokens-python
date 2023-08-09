from unittest.mock import patch

from pytest import mark

from supertokens_python.recipe.session.session_class import Session
from tests.sessions.claims.utils import NoneClaim, TrueClaim
from tests.utils import AsyncMock, MagicMock

pytestmark = (
    mark.asyncio
)  # no need to apply @mark.asyncio on each test because of this!


async def test_should_not_change_if_claim_fetch_value_returns_none():
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
        None,
        False,  # access_token_updated
        "public",
    )

    with patch.object(
        Session,
        "merge_into_access_token_payload",
        wraps=user_session.merge_into_access_token_payload,
    ) as mock:
        await user_session.fetch_and_set_claim(NoneClaim)
        mock.assert_called_once_with({}, {})


async def test_should_update_if_claim_fetch_value_returns_value(timestamp: int):
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
        await user_session.fetch_and_set_claim(TrueClaim)
        mock.assert_called_once_with({"st-true": {"t": timestamp, "v": True}}, {})
