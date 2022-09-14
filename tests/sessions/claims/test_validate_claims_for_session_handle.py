# Session.validateClaimsForSessionHandle
from unittest.mock import MagicMock
from pytest import mark

from supertokens_python.framework import BaseRequest
from supertokens_python import init
from supertokens_python.recipe import session
from supertokens_python.recipe.session.asyncio import (
    create_new_session,
    validate_claims_for_session_handle,
)
from supertokens_python.recipe.session.interfaces import (
    ClaimsValidationResult,
    SessionDoesNotExistError,
)
from tests.sessions.claims.utils import (
    get_st_init_args,
    NoneClaim,
    TrueClaim,
)
from tests.utils import setup_function, teardown_function, start_st, st_init_common_args

_ = setup_function  # type:ignore
_ = teardown_function  # type:ignore

pytestmark = mark.asyncio


async def test_should_return_the_right_validation_errors():
    init(**get_st_init_args(TrueClaim))  # type:ignore
    start_st()

    dummy_req: BaseRequest = MagicMock()
    s = await create_new_session(dummy_req, "someId")

    failing_validator = NoneClaim.validators.has_value(True)
    res = await validate_claims_for_session_handle(
        s.get_handle(),
        lambda _, __, ___: [TrueClaim.validators.has_value(True), failing_validator],
    )

    assert isinstance(res, ClaimsValidationResult) and len(res.invalid_claims) == 1
    assert res.invalid_claims[0].id == failing_validator.id
    assert res.invalid_claims[0].reason == {
        "message": "value does not exist",
        "actualValue": None,
        "expectedValue": True,
    }


async def test_should_work_for_not_existing_handle():
    new_st_init = {**st_init_common_args, "recipe_list": [session.init()]}
    init(**new_st_init)  # type: ignore
    start_st()

    res = await validate_claims_for_session_handle(
        "non_existing_handle", lambda _, __, ___: []
    )
    assert isinstance(res, SessionDoesNotExistError)
