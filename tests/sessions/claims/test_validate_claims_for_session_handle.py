# Session.validateClaimsForSessionHandle
from unittest.mock import MagicMock

from pytest import mark
from supertokens_python import init
from supertokens_python.framework import BaseRequest
from supertokens_python.recipe import session
from supertokens_python.recipe.session.asyncio import (
    create_new_session,
    validate_claims_for_session_handle,
)
from supertokens_python.recipe.session.interfaces import (
    ClaimsValidationResult,
    SessionDoesNotExistError,
)
from supertokens_python.types import RecipeUserId

from tests.sessions.claims.utils import (
    NoneClaim,
    TrueClaim,
    get_st_init_args,
)
from tests.utils import get_new_core_app_url
from tests.utils import get_st_init_args as base_get_st_init_args

pytestmark = mark.asyncio


async def test_should_return_the_right_validation_errors():
    init(**get_st_init_args(TrueClaim))

    dummy_req: BaseRequest = MagicMock()
    s = await create_new_session(dummy_req, "public", RecipeUserId("someId"))

    failing_validator = NoneClaim.validators.has_value(True)
    res = await validate_claims_for_session_handle(
        s.get_handle(),
        lambda _, __, ___: [TrueClaim.validators.has_value(True), failing_validator],
    )

    assert isinstance(res, ClaimsValidationResult) and len(res.invalid_claims) == 1
    assert res.invalid_claims[0].id_ == failing_validator.id
    assert res.invalid_claims[0].reason == {
        "message": "value does not exist",
        "actualValue": None,
        "expectedValue": True,
    }


async def test_should_work_for_not_existing_handle():
    new_st_init = base_get_st_init_args(
        url=get_new_core_app_url(),
        recipe_list=[
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie")
        ],
    )
    init(**new_st_init)

    res = await validate_claims_for_session_handle(
        "non-existing-handle", lambda _, __, ___: []
    )
    assert isinstance(res, SessionDoesNotExistError)
