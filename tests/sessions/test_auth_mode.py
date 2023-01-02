from typing import Any, Dict, Optional

from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient
from pytest import fixture, mark
from supertokens_python import init
from supertokens_python.framework.fastapi import get_middleware
from supertokens_python.recipe import session
from supertokens_python.recipe.session import SessionContainer
from supertokens_python.recipe.session.asyncio import create_new_session
from supertokens_python.recipe.session.framework.fastapi import verify_session
from supertokens_python.recipe.session.utils import TokenTransferMethod
from tests.utils import (
    extract_info,
    get_st_init_args,
    setup_function,
    start_st,
    teardown_function,
)

_ = setup_function  # type:ignore
_ = teardown_function  # type:ignore

pytestmark = mark.asyncio


@fixture(scope="function")
async def app():
    fast = FastAPI()
    fast.add_middleware(get_middleware())

    @fast.post("/create")
    async def _create(request: Request):  # type: ignore
        body = await request.json()
        session = await create_new_session(request, "userId", body, {})
        return {"message": True, "sessionHandle": session.get_handle()}

    @fast.post("/update-payload")
    async def _update_payload(session: SessionContainer = Depends(verify_session())):  # type: ignore
        await session.merge_into_access_token_payload({"newKey": "test"})
        return {"message": True}

    @fast.post("/verify")
    async def _verify(session: SessionContainer = Depends(verify_session())):  # type: ignore
        return {
            "message": True,
            "sessionHandle": session.get_handle(),
            "sessionExists": True,
        }

    @fast.post("/verify-optional")
    async def _verify_optional(session: Optional[SessionContainer] = Depends(verify_session(session_required=True))):  # type: ignore
        return {
            "message": True,
            "sessionHandle": session.get_handle() if session is not None else None,
            "sessionExists": session is not None,
        }

    return TestClient(fast)


# from dataclasses import dataclass


# @dataclass
# class ResponseInfo:
#     access_token: Optional[str]
#     refresh_token: Optional[str]
#     anti_csrf: Optional[str]


EXAMPLE_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"


def create_session(
    app: TestClient,
    auth_mode_header: Optional[str] = None,
    body: Optional[Dict[str, Any]] = None,
    cookies: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, Any]] = None,
):
    if headers is None:
        headers = {}
    if cookies is None:
        cookies = {}

    if auth_mode_header is not None:
        headers["st-auth-mode"] = auth_mode_header

    res = app.post(url="/create", headers=headers, json=body or {}, cookies=cookies)

    return extract_info(res)


def check_extracted_info(
    res: Dict[str, Any], expected_transfer_method: TokenTransferMethod
):
    if expected_transfer_method == "header":
        for prop in ["accessToken", "refreshToken", "antiCsrf"]:
            assert res.get(prop) is None
        for prop in ["accessTokenFromHeader", "refreshTokenFromHeader"]:
            assert res.get(prop) is not None

        # We check that we will have access token at least as long as we have a refresh token
        # so verify session can return TRY_REFRESH_TOKEN
        # assert res["accessTokenFromHeader"]["expiry"] >= res["refreshTokenFromHeader"]["expiry"]
    elif expected_transfer_method == "cookie":
        for prop in ["accessToken", "refreshToken", "antiCsrf"]:
            assert res.get(prop) is not None
        for prop in ["accessTokenFromHeader", "refreshTokenFromHeader"]:
            assert res.get(prop) is None
        # We check that we will have access token at least as long as we have a refresh token
        # so verify session can return TRY_REFRESH_TOKEN
        # assert datetime.parse(res["accessTokenExpiry"]) >= datetime.parse(res["refreshTokenExpiry"])
    else:
        assert False, "Invalid expected_transfer_method"


@mark.parametrize(
    "auth_mode_header, expected_transfer_method",
    [
        (None, "header"),  # default
        ("invalid-token-transfer-method", "header"),  # invalid
        ("header", "header"),  # specified
        ("cookie", "cookie"),  #  specified
    ],
)
async def test_should_follow_auth_mode_header(
    app: TestClient,
    auth_mode_header: Optional[str],
    expected_transfer_method: TokenTransferMethod,
):
    init(**get_st_init_args([session.init(anti_csrf="VIA_TOKEN")]))  # type:ignore
    start_st()

    res = create_session(app, auth_mode_header)

    check_extracted_info(res, expected_transfer_method)


# @mark.parametrize(
#     "token_transfer_method, expected_transfer_method, **kwargs",
#     [
#         ("any", "header"),  # default
#         ("header", "header", {"cookies": {"sAccessToken": EXAMPLE_JWT}}),  # specified
#         ("cookie", "cookie"),  #  specified
#         (
#             "cookie",
#             "cookie",
#             {"headers": {"Authorization": f"Bearer {EXAMPLE_JWT}"}},
#         ),  #  specified
#     ],
# )
# async def test_should_follow_get_token_transfer_method(
#     app: TestClient,
#     token_transfer_method: Optional[str],
#     expected_transfer_method: TokenTransferMethod,
#     *args,
#     **kwargs,
# ):
#     init(
#         **get_st_init_args(
#             [
#                 session.init(
#                     anti_csrf="VIA_TOKEN",
#                     get_token_transfer_method=lambda _, __, ___: token_transfer_method,
#                 )
#             ]
#         )
#     )  # type:ignore
#     start_st()

#     cookies: Optional[Dict[str, Any]] = None
#     cookies = kwargs.get("cookies")  # type: ignore

#     headers: Optional[Dict[str, Any]] = None
#     headers = kwargs.get("headers")  # type: ignore

#     res = create_session(app, None, None, cookies=cookies, headers=headers)

#     check_extracted_info(res, expected_transfer_method)

#     if cookies is not None and expected_transfer_method == "header":
#         assert res["accessToken"] == ""
#         assert res["accessTokenExpiry"] == "Thu, 01 Jan 1970 00:00:00 GMT"
#         assert res["refreshToken"] == ""
#         assert res["refreshTokenExpiry"] == "Thu, 01 Jan 1970 00:00:00 GMT"
#         assert res.get("antiCsrf") is None

#     if headers is not None and expected_transfer_method == "cookie":
#         assert res["accessTokenFromHeader"]["value"] == ""
#         assert res["accessTokenFromHeader"]["expiry"] == 0
#         assert res["refreshTokenFromHeader"] == ""
#         assert res["refreshTokenFromHeader"]["expiry"] == 0


# @mark.parametrized(
#     "transfer_method, session_required, auth_header, auth_cookie, result",
#     [
#         ("any", False, False, False, None),
#         ("header", False, False, False, None),
#         ("cookie", False, False, False, None),
#         ("cookie", False, True, False, None),
#         ("header", False, False, True, None),
#         ("any", True, False, False, "UNAUTHORISED"),
#         ("header", True, False, False, "UNAUTHORISED"),
#         ("cookie", True, False, False, "UNAUTHORISED"),
#         ("cookie", True, True, False, "UNAUTHORISED"),
#         ("header", True, False, True, "UNAUTHORISED"),
#         ("any", True, True, True, "validateheader"),
#         ("any", False, True, True, "validateheader"),
#         ("header", True, True, True, "validateheader"),
#         ("header", False, True, True, "validateheader"),
#         ("cookie", True, True, True, "validatecookie"),
#         ("cookie", False, True, True, "validatecookie"),
#         ("any", True, True, False, "validateheader"),
#         ("any", False, True, False, "validateheader"),
#         ("header", True, True, False, "validateheader"),
#         ("header", False, True, False, "validateheader"),
#         ("any", True, False, True, "validatecookie"),
#         ("any", False, False, True, "validatecookie"),
#         ("cookie", True, False, True, "validatecookie"),
#         ("cookie", False, False, True, "validatecookie"),
#     ],
# )
# def test_verify_session_parametrized(
#     app: TestClient,
#     transfer_method: TokenTransferMethod,
#     session_required: bool,
#     auth_header: bool,
#     auth_cookie: bool,
#     result: Optional[str],
# ):
#     init(
#         **get_st_init_args(
#             [
#                 session.init(
#                     anti_csrf="VIA_TOKEN",
#                     get_token_transfer_method=lambda _, __, ___: transfer_method,
#                 )
#             ]
#         )
#     )
#     start_st()

#     res = create_session(app, "cookie")

#     if use_expired_token:
#         delay(3)

#     auth_mode = "none"
#     if auth_cookie and auth_header:
#         auth_mode = "both"
#     if auth_header:
#         auth_mode = "header"
#     if auth_cookie:
#         auth_mode = "cookie"

#     res = test_get(
#         app,
#         res,
#         "/verify" if session_required else "/verify-optional",
#         auth_mode,
#     )
#     assert res.status_code == (401 if result == "UNAUTHORISED" else 200)

#     body = res.json()

#     if result == None:
#         assert body["sesionExists"] == False
#     if result == "UNAUTHORISED":
#         assert body["message"] == "UNAUTHORISED"
#     if result in ("validateCookie", "validateHeader"):
#         assert body["sessionExists"] == True


# # Skipping the following 3 tests as they are covered by previous tests:
# # Provide access token via both header and cookie. It should use the value from headers if getTokenTransferMethod returns header or any. If returns cookie, it should use the value from cookie.


# async def test_should_reject_requests_with_sIdRefreshToken(app: TestClient):
#     init(**get_st_init_args([session.init(anti_csrf="VIA_TOKEN")]))
#     start_st()

#     res = create_session(
#         app,
#         "cookie",
#         None,
#         cookies={"sIdRefreshToken": "IRRELEVANT-VALUE", "sAccessToken": EXAMPLE_JWT},
#     )

#     response = app.post(
#         url="/verify",
#         cookies={
#             "sIdRefreshToken": "IRRELEVANT-VALUE",
#             "sAccessToken": EXAMPLE_JWT,
#         },
#         headers={"anti-csrf": res["antiCsrf"]},
#     )

#     assert response.status_code == 401
#     assert response.json() == {"message": "try refresh token"}


# # SKIPPING:
# # with non ST in Authorize header
# # should use the value from cookies if present and getTokenTransferMethod returns {any,header,cookie}


# # merge_into_access_token_payload


# @mark.parametrize("transfer_method", [("header",), ("cookie",)])
# async def test_should_update_acccess_token_payload(
#     app: TestClient, transfer_method: str
# ):
#     init(**get_st_init_args([session.init(anti_csrf="VIA_TOKEN")]))
#     start_st()

#     res = create_session(app, transfer_method)

#     update_info = extract_info(
#         await test_get(app, res, "/update-payload", 200, "cookie", None).json()
#     )

#     assert update_info.keys() == {"accessToken", "frontToken"}

#     assert update_info["accessToken"] != res["accessTokenFromHeader"]
#     assert update_info["frontToken"] != res["frontToken"]


# @mark.parametrized(
#     "transfer_method, session_required, auth_header, auth_cookie, result",
#     [
#         ("any", False, "unauthorised", None, None),
#         ("header", False, "unauthorised", None, None),
#         ("cookie", False, "unauthorised", None, None),
#         ("any", False, "validatecookie", "cookies", None),
#         ("header", False, "unauthorised", None, None),
#         ("cookie", False, "validatecookie", "cookies", None),
#         ("any", True, "validateheader", "headers", None),
#         ("header", True, "validateheader", "headers", None),
#         ("cookie", True, "unauthorised", None, None),
#         ("any", True, "validateheader", "headers", "cookies"),
#         ("header", True, "validateheader", "headers", "cookies"),
#         ("cookie", True, "validatecookie", "cookies", "headers"),
#     ],
# )
# def test_refresh_session_parametrized(
#     app: TestClient,
#     transfer_method: TokenTransferMethod,
#     session_required: bool,
#     auth_header: bool,
#     auth_cookie: bool,
#     result: Optional[str],
#     set_tokens: Optional[str],
#     cleared_tokens: Optional[str],
# ):
#     init(
#         **get_st_init_args(
#             [
#                 session.init(
#                     anti_csrf="VIA_TOKEN",
#                     get_token_transfer_method=lambda _, __, ___: transfer_method,
#                 )
#             ]
#         )
#     )
#     start_st()

#     # Token transfer method doesn't matter for this test
#     res = create_session(app, "header")

#     auth_mode = "none"
#     if auth_cookie and auth_header:
#         auth_mode = "both"
#     if auth_header:
#         auth_mode = "header"
#     if auth_cookie:
#         auth_mode = "cookie"

#     refresh_result = await refresh_session(app, transfer_method, auth_mode, res)

#     if output == "unauthorised":
#         assert refresh_result.status_code == 401
#         assert refresh_result.json() == {"message": "unauthorised"}
#     else:
#         assert refresh_result.status_code == 200

#     if cleared_tokens == "headers":
#         assert refresh_result["access_token_from_header"] == ""
#         assert refresh_result["refresh_token_from_header"] == ""
#     elif cleared_tokens == "cookies":
#         assert refresh_result["access_token"] == ""
#         assert refresh_result["accessTokenExpiry"] == "Thu, 01 Jan 1970 00:00:00 GMT"
#         assert refresh_result["refresh_token"] == ""
#         assert refresh_result["refreshTokenExpiry"] == "Thu, 01 Jan 1970 00:00:00 GMT"

#     if set_tokens == "headers":
#         assert refresh_result["access_token_from_header"] != ""
#         assert refresh_result["refresh_token_from_header"] != ""
#     elif set_tokens == "cookies":
#         assert refresh_result["access_token"] != ""
#         assert refresh_result["accessTokenExpiry"] != "Thu, 01 Jan 1970 00:00:00 GMT"
#         assert refresh_result["refresh_token"] != ""
#         assert refresh_result["refreshTokenExpiry"] != "Thu, 01 Jan 1970 00:00:00 GMT"
#     elif set_tokens == None:
#         if cleared_tokens == None:
#             assert "frontToken" not in refresh_result
#     else:
#         assert False, "Invalid set_tokens value"

#     if set_tokens != "cookies" and cleared_tokens != "cookies":
#         assert refresh_result.keys() == {}  # FIXME
#     elif set_tokens != "headers" and cleared_tokens != "headers":
#         assert refresh_result.keys() == {}  # FIXME
#     else:
#         assert False, "Invalid set_tokens and cleared_tokens values"
