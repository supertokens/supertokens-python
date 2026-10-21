from typing import Any, Dict

import pytest
from supertokens_python import init
from supertokens_python.recipe import session
from supertokens_python.recipe.session import session_functions
from supertokens_python.recipe.session.access_token import get_info_from_access_token
from supertokens_python.recipe.session.asyncio import (
    create_new_session_without_request_response,
    get_session_without_request_response,
)
from supertokens_python.recipe.session.exceptions import (
    TryRefreshTokenError,
    UnauthorisedError,
)
from supertokens_python.recipe.session.jwt import (
    parse_jwt_without_signature_verification,
)
from supertokens_python.recipe.session.recipe import SessionRecipe
from supertokens_python.types import RecipeUserId

from tests.utils import get_new_core_app_url, get_st_init_args


async def create_core_signed_access_token(access_token_payload: Dict[str, Any]) -> str:
    # Creates the session directly through the core, so the payload reaches the token unchanged
    recipe_implementation: Any = SessionRecipe.get_instance().recipe_implementation
    res = await session_functions.create_new_session(
        recipe_implementation,
        "public",
        RecipeUserId("user-id"),
        True,
        access_token_payload,
        {},
        {},
    )
    return res.accessToken.token


async def test_core_signed_token_with_a_non_session_token_type_is_rejected():
    init(**get_st_init_args(url=get_new_core_app_url(), recipe_list=[session.init()]))  # type: ignore

    access_token = await create_core_signed_access_token({"stt": 1})
    parsed_info = parse_jwt_without_signature_verification(access_token)
    assert parsed_info.payload["stt"] == 1

    with pytest.raises(TryRefreshTokenError):
        get_info_from_access_token(
            SessionRecipe.get_instance().config, parsed_info, False
        )

    with pytest.raises(UnauthorisedError):
        await get_session_without_request_response(access_token)

    assert (
        await get_session_without_request_response(access_token, session_required=False)
        is None
    )


@pytest.mark.parametrize("access_token_payload", [{}, {"stt": 0}])
async def test_core_signed_token_with_session_token_type_or_none_is_accepted(
    access_token_payload: Dict[str, Any],
):
    init(**get_st_init_args(url=get_new_core_app_url(), recipe_list=[session.init()]))  # type: ignore

    access_token = await create_core_signed_access_token(access_token_payload)

    s = await get_session_without_request_response(access_token)
    assert s is not None
    assert s.get_user_id() == "user-id"


async def test_token_type_is_removed_from_the_payload_passed_to_create_new_session():
    init(**get_st_init_args(url=get_new_core_app_url(), recipe_list=[session.init()]))  # type: ignore

    s = await create_new_session_without_request_response(
        "public", RecipeUserId("user-id"), {"stt": 1, "custom": "value"}
    )
    payload = parse_jwt_without_signature_verification(s.get_access_token()).payload
    assert "stt" not in payload
    assert payload["custom"] == "value"

    verified = await get_session_without_request_response(s.get_access_token())
    assert verified is not None
    assert verified.get_user_id() == "user-id"
