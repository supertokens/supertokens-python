from fastapi import FastAPI
from fastapi.requests import Request
from jwt import decode
from pytest import fixture
from starlette.testclient import TestClient
from supertokens_python import init
from supertokens_python.framework.fastapi import get_middleware
from supertokens_python.recipe.session import JWTConfig
from supertokens_python.recipe.session.asyncio import (
    create_new_session,
    get_session_information,
    validate_claims_in_jwt_payload,
)
from supertokens_python.recipe.session.interfaces import ClaimsValidationResult
from tests.sessions.claims.utils import NoneClaim, TrueClaim, get_st_init_args
from tests.utils import min_api_version, setup_function, start_st, teardown_function

_ = setup_function  # type:ignore
_ = teardown_function  # type:ignore


@fixture(scope="function")
async def fastapi_client():
    app = FastAPI()
    app.add_middleware(get_middleware())

    @app.post("/create")
    async def create_api(request: Request):  # type: ignore
        user_id = "userId"
        s = await create_new_session(request, user_id, {}, {})
        return {"session_handle": s.get_handle()}

    @app.post("/merge-test-claim-and-return-jwt")
    async def merge_claim_and_return_jwt(request: Request):  # type: ignore
        user_id = "user_id"
        s = await create_new_session(request, user_id, {}, {})
        await s.merge_into_access_token_payload({"test_claim": "value"})
        return {"jwt": s.get_access_token_payload()["jwt"]}

    return TestClient(app)


@min_api_version("2.9")
async def test_should_create_the_right_access_token_payload_with_claims_and_JWT_enabled(
    fastapi_client: TestClient,
):
    init(**get_st_init_args(TrueClaim, jwt=JWTConfig(enable=True)))  # type:ignore
    start_st()

    create_res = fastapi_client.post(url="/create")
    session_handle = create_res.json()["session_handle"]

    session_info = await get_session_information(session_handle)
    assert session_info is not None
    access_token_payload = session_info.access_token_payload
    assert access_token_payload["jwt"] is not None
    assert access_token_payload["_jwtPName"] == "jwt"

    decoded_jwt = decode(
        jwt=access_token_payload["jwt"], options={"verify_signature": False}
    )

    assert (
        decoded_jwt.items()
        >= {
            "sub": "userId",
            "st-true": {"v": True, "t": decoded_jwt["st-true"]["t"]},
            "iss": "http://api.supertokens.io/auth",
        }.items()
    )

    assert TrueClaim.get_value_from_payload(access_token_payload) is True
    assert TrueClaim.get_value_from_payload(decoded_jwt) is True

    failing_validator = NoneClaim.validators.has_value(True)
    res = await validate_claims_in_jwt_payload(
        session_info.user_id,
        decoded_jwt,
        lambda _, __, ___: [
            TrueClaim.validators.has_value(True, 100),
            failing_validator,
        ],
    )

    assert isinstance(res, ClaimsValidationResult) and len(res.invalid_claims) == 1
    assert res.invalid_claims[0].id == failing_validator.id

    assert res.invalid_claims[0].reason == {
        "actualValue": None,
        "expectedValue": True,
        "message": "value does not exist",
    }


@min_api_version("2.9")
async def test_jwt_should_contain_claim_merged_into_access_token_payload(
    fastapi_client: TestClient,
):
    init(**get_st_init_args(TrueClaim, jwt=JWTConfig(enable=True)))  # type:ignore
    start_st()

    create_res = fastapi_client.post(url="/merge-test-claim-and-return-jwt")
    jwt = create_res.json()["jwt"]

    decoded_jwt = decode(jwt, options={"verify_signature": False})
    assert decoded_jwt["test_claim"] == "value"
