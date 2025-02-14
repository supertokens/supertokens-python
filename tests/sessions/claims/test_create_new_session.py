from unittest.mock import MagicMock

from supertokens_python import init
from supertokens_python.framework import BaseRequest
from supertokens_python.recipe import session
from supertokens_python.recipe.session.asyncio import create_new_session
from supertokens_python.types import RecipeUserId

from tests.utils import (
    get_new_core_app_url,
    min_api_version,
)
from tests.utils import (
    get_st_init_args as base_get_st_init_args,
)

from .utils import (
    NoneClaim,
    TrueClaim,
    get_st_init_args,
    session_functions_override_with_claim,
)


@min_api_version("2.13")
async def test_create_access_token_payload_with_session_claims(timestamp: int):
    init(**get_st_init_args(TrueClaim))

    dummy_req: BaseRequest = MagicMock()
    s = await create_new_session(dummy_req, "public", RecipeUserId("someId"))

    payload = s.get_access_token_payload()
    assert len(payload) == 11
    assert payload["st-true"] == {"v": True, "t": timestamp}


@min_api_version("2.13")
async def test_should_create_access_token_payload_with_session_claims_with_an_none_value():
    init(**get_st_init_args(NoneClaim))

    dummy_req: BaseRequest = MagicMock()
    s = await create_new_session(dummy_req, "public", RecipeUserId("someId"))

    payload = s.get_access_token_payload()
    assert len(payload) == 10
    assert payload.get("st-true") is None


@min_api_version("2.13")
async def test_should_merge_claims_and_passed_access_token_payload_obj(timestamp: int):
    new_st_init = base_get_st_init_args(
        url=get_new_core_app_url(),
        recipe_list=[
            session.init(
                override=session.InputOverrideConfig(
                    functions=session_functions_override_with_claim(
                        TrueClaim, {"user-custom-claim": "foo"}
                    ),
                )
            ),
        ],
    )
    init(**new_st_init)

    dummy_req: BaseRequest = MagicMock()
    s = await create_new_session(dummy_req, "public", RecipeUserId("someId"))

    payload = s.get_access_token_payload()
    assert len(payload) == 12
    assert payload["st-true"] == {"v": True, "t": timestamp}
    assert payload["user-custom-claim"] == "foo"
