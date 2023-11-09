from typing import Optional, Dict, Any
import pytest
from fastapi import Depends, FastAPI, Request

from supertokens_python import init
from supertokens_python.framework.fastapi import get_middleware
from supertokens_python.recipe import session
from supertokens_python.recipe.session.access_token import get_info_from_access_token
from supertokens_python.recipe.session.asyncio import (
    create_new_session_without_request_response,
    get_session_without_request_response,
)
from supertokens_python.recipe.session.jwt import (
    parse_jwt_without_signature_verification,
)
from supertokens_python.recipe.session.access_token import (
    validate_access_token_structure,
)
from tests.utils import get_st_init_args, setup_function, start_st, teardown_function

_ = setup_function  # type:ignore
_ = teardown_function  # type:ignore

pytestmark = pytest.mark.asyncio


async def test_access_token_v4():
    init(**get_st_init_args([session.init()]))  # type:ignore
    start_st()

    access_token = (
        await create_new_session_without_request_response("public", "user-id")
    ).get_access_token()
    s = await get_session_without_request_response(access_token)
    assert s is not None
    assert s.get_user_id() == "user-id"

    parsed_info = parse_jwt_without_signature_verification(access_token)

    res = get_info_from_access_token(
        parsed_info,
        False,
    )
    assert res["userId"] == "user-id"
    assert parsed_info.version == 4


async def test_parsing_access_token_v2():
    v2_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsInZlcnNpb24iOiIyIn0=.eyJzZXNzaW9uSGFuZGxlIjoiZWI3ZjBkNTUtNjgwNy00NDFkLTlhNjEtM2VhM2IyNmZiNWQwIiwidXNlcklkIjoiNmZiNGRkY2UtODkxMS00MDU4LTkyYWMtYzc2MDU3ZmRhYWU4IiwicmVmcmVzaFRva2VuSGFzaDEiOiJjOTA0OTk2YzEzZmFjMzc2ZjllMmI2MTM0OTg4MjUyYTc1NjAzNGY0ZTAzYmYxMGQ3NGUyOTA0MjE2OWQzZjkxIiwicGFyZW50UmVmcmVzaFRva2VuSGFzaDEiOm51bGwsInVzZXJEYXRhIjp7fSwiYW50aUNzcmZUb2tlbiI6bnVsbCwiZXhwaXJ5VGltZSI6MTY4MzIwNzE2NDM2NSwidGltZUNyZWF0ZWQiOjE2ODMyMDM1NjQzNjUsImxtcnQiOjE2ODMyMDM1NjQzNjV9.MYtsq8yc3/gAymFd148oDdHvH1p6T67lNhnSEUJ+Kroxx4Lv2sdFrvpyQ4m8fHfN0g1C6nOSqMArQarj4hDqykFR9YbpUPdKyEg/rnPhoRR7BtgYg05fQ46EURkItnHNCywBC/vyvJLyG2tzGYWPzXchbr7DySxp+mBsu9AeFTUUqCw9W2bJ5VWIILhqlR7S/QH2yl3bRbwb0VaqUe+Ekc/68tKCpOnsg2ukWDSBVOWxXxr8/odYLdVyu8xyyH71GTol62jqrCkSDyQ0pnhyGspAaaT398QOYCwOV98ztrrvVNtoFLs8TW/aVj3kBHHUT29OY8yEs2odksIaL48J2w=="

    parsed_info = parse_jwt_without_signature_verification(v2_token)
    assert parsed_info is not None
    assert parsed_info.version == 2
    assert parsed_info.kid is None
    assert parsed_info.payload["userId"] == "6fb4ddce-8911-4058-92ac-c76057fdaae8"


from fastapi.testclient import TestClient

from supertokens_python.recipe.session.interfaces import SessionContainer
from supertokens_python.recipe.session.asyncio import create_new_session
from supertokens_python.recipe.session.framework.fastapi import verify_session
from supertokens_python.querier import Querier, NormalisedURLPath
from tests.utils import extract_info


@pytest.fixture(scope="function")
async def app():
    fast = FastAPI()
    fast.add_middleware(get_middleware())

    @fast.post("/create")
    async def _create(request: Request):  # type: ignore
        body: Dict[str, Any] = {}
        try:
            body = await request.json()
        except Exception:
            pass

        session = await create_new_session(request, "public", "userId", body, {})
        return {"message": True, "sessionHandle": session.get_handle()}

    @fast.get("/merge-into-payload")
    async def _update_payload(session: SessionContainer = Depends(verify_session())):  # type: ignore
        await session.merge_into_access_token_payload({"newKey": "test"})
        return {"message": True}

    @fast.get("/verify")
    async def _verify(session: SessionContainer = Depends(verify_session())):  # type: ignore
        return {
            "message": True,
            "sessionHandle": session.get_handle(),
            "sessionExists": True,
            "payload": session.get_access_token_payload(),
        }

    @fast.get("/verify-checkdb")
    async def _verify_checkdb(session: SessionContainer = Depends(verify_session(check_database=True))):  # type: ignore
        return {
            "message": True,
            "sessionHandle": session.get_handle(),
            "sessionExists": True,
            "payload": session.get_access_token_payload(),
        }

    @fast.get("/verify-optional")
    async def _verify_optional(session: Optional[SessionContainer] = Depends(verify_session(session_required=False))):  # type: ignore
        return {
            "message": True,
            "sessionHandle": session.get_handle() if session is not None else None,
            "sessionExists": session is not None,
        }

    @fast.get("/revoke-session")
    async def _revoke_session(session: SessionContainer = Depends(verify_session())):  # type: ignore
        return {
            "messsage": (await session.revoke_session()),
            "sessionHandle": session.get_handle(),
        }

    return TestClient(fast)


async def test_should_validate_v2_tokens_with_check_database_enabled(app: TestClient):
    init(**get_st_init_args([session.init()]))  # type:ignore
    start_st()

    # This CDI version is no longer supported by this SDK, but we want to ensure that sessions keep working after the upgrade
    # We can hard-code the structure of the request&response, since this is a fixed CDI version and it's not going to change
    Querier.api_version = "2.8"
    q = Querier.get_instance()
    legacy_session_resp = await q.send_post_request(
        NormalisedURLPath("/recipe/session"),
        {
            "userId": "test-user-id",
            "enableAntiCsrf": False,
            "userDataInJWT": {},
            "userDataInDatabase": {},
        },
        None,
    )
    Querier.api_version = None

    legacy_token = legacy_session_resp["accessToken"]["token"]

    revoke_session_res = app.get(
        "/revoke-session", headers={"Authorization": "Bearer " + legacy_token}
    )
    assert revoke_session_res.status_code == 200

    verify_check_db_res = app.get(
        "/verify-checkdb", headers={"Authorization": "Bearer " + legacy_token}
    )
    assert verify_check_db_res.status_code == 401

    assert verify_check_db_res.json() == {"message": "unauthorised"}

    verify_res = app.get("/verify", headers={"Authorization": "Bearer " + legacy_token})
    assert verify_res.status_code == 200

    verify_res_json = verify_res.json()
    assert verify_res_json.pop("payload") == {}
    assert verify_res_json == {
        "message": True,
        "sessionExists": True,
        "sessionHandle": legacy_session_resp["session"]["handle"],
    }


async def test_should_validate_v3_tokens_with_check_database_enabled(app: TestClient):
    init(**get_st_init_args([session.init()]))  # type:ignore
    start_st()

    create_session_res = app.post("/create", data={})
    info = extract_info(create_session_res)
    assert info["accessTokenFromAny"] is not None
    assert info["refreshTokenFromAny"] is not None
    assert info["frontToken"] is not None

    access_token = info["accessTokenFromAny"]

    revoke_session_res = app.get(
        "/revoke-session", headers={"Authorization": "Bearer " + access_token}
    )
    assert revoke_session_res.status_code == 200

    verify_check_db_res = app.get(
        "/verify-checkdb", headers={"Authorization": "Bearer " + access_token}
    )
    assert verify_check_db_res.status_code == 401

    assert verify_check_db_res.json() == {"message": "unauthorised"}

    verify_res = app.get("/verify", headers={"Authorization": "Bearer " + access_token})
    assert verify_res.status_code == 200

    verify_res_json = verify_res.json()

    assert verify_res_json.pop("payload") != {}
    assert verify_res_json == {
        "message": True,
        "sessionExists": True,
        "sessionHandle": info["body"]["sessionHandle"],
    }


async def test_ignore_protected_props_in_create_session():
    init(**get_st_init_args([session.init()]))
    start_st()

    s = await create_new_session_without_request_response(
        "public",
        "user1",
        {"foo": "bar"},
    )
    payload = parse_jwt_without_signature_verification(s.access_token).payload
    assert payload["foo"] == "bar"
    assert payload["sub"] == "user1"

    s2 = await create_new_session_without_request_response(
        "public", "user2", s.get_access_token_payload()
    )
    payload = parse_jwt_without_signature_verification(s2.access_token).payload
    assert payload["foo"] == "bar"
    assert payload["sub"] == "user2"


async def test_validation_logic_with_keys_that_can_use_json_nulls_values_in_claims():
    """We want to make sure that for access token claims that can be null, the SDK does not fail access token validation if the
    core does not send them as part of the payload. For this we verify that validation passes when the keys are None, empty,
    or of a different type.

    For now this test checks for:
    - antiCsrfToken
    - parentRefreshTokenHash1

    But this test should be updated to include any keys that the core considers optional in the payload (i.e either it sends
    JSON null or skips them entirely)
    """

    V3 = 3
    payload = {
        "sessionHandle": "",
        "sub": "",
        "refreshTokenHash1": "",
        "exp": float(0),
        "iat": float(0),
    }

    validate_access_token_structure(payload, V3)

    payload = {
        "sessionHandle": "",
        "sub": "",
        "refreshTokenHash1": "",
        "exp": float(0),
        "iat": float(0),
        "parentRefreshTokenHash1": None,
        "antiCsrfToken": None,
    }

    validate_access_token_structure(payload, V3)

    payload = {
        "sessionHandle": "",
        "sub": "",
        "refreshTokenHash1": "",
        "exp": float(0),
        "iat": float(0),
        "parentRefreshTokenHash1": "",
        "antiCsrfToken": "",
    }

    validate_access_token_structure(payload, V3)

    payload = {
        "sessionHandle": "",
        "sub": "",
        "refreshTokenHash1": "",
        "exp": float(0),
        "iat": float(0),
        "parentRefreshTokenHash1": 1,
        "antiCsrfToken": 1,
    }

    validate_access_token_structure(payload, V3)
