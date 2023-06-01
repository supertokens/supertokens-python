import pytest

from supertokens_python import init
from supertokens_python.recipe import session
from supertokens_python.recipe.session.access_token import get_info_from_access_token
from supertokens_python.recipe.session.asyncio import (
    create_new_session_without_request_response,
    get_session_without_request_response,
)
from supertokens_python.recipe.session.jwt import (
    parse_jwt_without_signature_verification,
)
from supertokens_python.recipe.session.recipe import SessionRecipe
from tests.utils import get_st_init_args, setup_function, start_st, teardown_function

_ = setup_function  # type:ignore
_ = teardown_function  # type:ignore

pytestmark = pytest.mark.asyncio


async def test_access_token_v3():
    init(**get_st_init_args([session.init()]))  # type:ignore
    start_st()

    access_token = (
        await create_new_session_without_request_response("user-id")
    ).get_access_token()
    s = await get_session_without_request_response(access_token)
    assert s is not None
    assert s.get_user_id() == "user-id"

    parsed_info = parse_jwt_without_signature_verification(access_token)

    recipe_implementation = SessionRecipe.get_instance().recipe_implementation

    res = get_info_from_access_token(
        parsed_info,
        recipe_implementation.JWK_clients,
        False,
    )
    assert res["userId"] == "user-id"


async def test_parsing_access_token_v2():
    v2_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsInZlcnNpb24iOiIyIn0=.eyJzZXNzaW9uSGFuZGxlIjoiZWI3ZjBkNTUtNjgwNy00NDFkLTlhNjEtM2VhM2IyNmZiNWQwIiwidXNlcklkIjoiNmZiNGRkY2UtODkxMS00MDU4LTkyYWMtYzc2MDU3ZmRhYWU4IiwicmVmcmVzaFRva2VuSGFzaDEiOiJjOTA0OTk2YzEzZmFjMzc2ZjllMmI2MTM0OTg4MjUyYTc1NjAzNGY0ZTAzYmYxMGQ3NGUyOTA0MjE2OWQzZjkxIiwicGFyZW50UmVmcmVzaFRva2VuSGFzaDEiOm51bGwsInVzZXJEYXRhIjp7fSwiYW50aUNzcmZUb2tlbiI6bnVsbCwiZXhwaXJ5VGltZSI6MTY4MzIwNzE2NDM2NSwidGltZUNyZWF0ZWQiOjE2ODMyMDM1NjQzNjUsImxtcnQiOjE2ODMyMDM1NjQzNjV9.MYtsq8yc3/gAymFd148oDdHvH1p6T67lNhnSEUJ+Kroxx4Lv2sdFrvpyQ4m8fHfN0g1C6nOSqMArQarj4hDqykFR9YbpUPdKyEg/rnPhoRR7BtgYg05fQ46EURkItnHNCywBC/vyvJLyG2tzGYWPzXchbr7DySxp+mBsu9AeFTUUqCw9W2bJ5VWIILhqlR7S/QH2yl3bRbwb0VaqUe+Ekc/68tKCpOnsg2ukWDSBVOWxXxr8/odYLdVyu8xyyH71GTol62jqrCkSDyQ0pnhyGspAaaT398QOYCwOV98ztrrvVNtoFLs8TW/aVj3kBHHUT29OY8yEs2odksIaL48J2w=="

    parsed_info = parse_jwt_without_signature_verification(v2_token)
    assert parsed_info is not None
    assert parsed_info.version == 2
    assert parsed_info.kid is None
    assert parsed_info.payload["userId"] == "6fb4ddce-8911-4058-92ac-c76057fdaae8"
