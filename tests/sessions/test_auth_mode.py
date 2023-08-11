from typing import Any, Dict, Optional, Union
from typing_extensions import Literal

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
        session = await create_new_session(request, "public", "userId", body, {})
        return {"message": True, "sessionHandle": session.get_handle()}

    @fast.get("/update-payload")
    async def _update_payload(session: SessionContainer = Depends(verify_session())):  # type: ignore
        await session.merge_into_access_token_payload({"newKey": "test"})
        return {"message": True}

    @fast.get("/verify")
    async def _verify(session: SessionContainer = Depends(verify_session())):  # type: ignore
        return {
            "message": True,
            "sessionHandle": session.get_handle(),
            "sessionExists": True,
        }

    @fast.get("/verify-optional")
    async def _verify_optional(session: Optional[SessionContainer] = Depends(verify_session(session_required=False))):  # type: ignore
        return {
            "message": True,
            "sessionHandle": session.get_handle() if session is not None else None,
            "sessionExists": session is not None,
        }

    return TestClient(fast)


from requests.cookies import RequestsCookieJar


def call_api(
    app: TestClient,
    info: Dict[str, Any],
    url: str,
    expected_status: int,
    auth_mode: str,
    auth_mode_header: Optional[str] = None,
):
    access_token = info.get("accessTokenFromAny")

    headers = {}
    cookies = {}

    if auth_mode_header:
        headers["st-auth-mode"] = auth_mode_header
    if auth_mode in ("cookie", "both"):
        cookies["sAccessToken"] = access_token
        if info.get("antiCsrf") is not None:
            headers["anti-csrf"] = info["antiCsrf"]

    if auth_mode in ("header", "both"):
        headers[
            "Authorization"
        ] = f"Bearer {(access_token)}"  # TODO: Might have to add decode_uri()

    app.cookies = RequestsCookieJar()  # Reset cookies

    res = app.get(
        url=url,
        headers=headers,
        cookies=cookies,
    )

    assert res.status_code == expected_status
    return res


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
    res: Dict[str, Any],
    expected_transfer_method: TokenTransferMethod,
    passed_different_token: bool = False,
):
    if expected_transfer_method == "header":
        for prop in ["accessToken", "refreshToken"]:
            if (
                passed_different_token
            ):  # If method is header but we passed a different token in cookie with request
                assert (
                    res.get(prop, "") == ""
                )  # It should clear the cookie (if present)
            else:
                assert res[prop] is None
        assert res["antiCsrf"] is None
        for prop in ["accessTokenFromHeader", "refreshTokenFromHeader"]:
            assert res[prop] != ""

        # We check that we will have access token at least as long as we have a refresh token
        # so verify session can return TRY_REFRESH_TOKEN
        # assert res["accessTokenFromHeader"]["expiry"] >= res["refreshTokenFromHeader"]["expiry"]
    elif expected_transfer_method == "cookie":
        for prop in ["accessToken", "refreshToken", "antiCsrf"]:
            assert res[prop] != ""
        for prop in ["accessTokenFromHeader", "refreshTokenFromHeader"]:
            if (
                passed_different_token
            ):  # If method is cookie but we passed a different token in header with request
                assert res.get(prop, "") == ""  # clear the header (if present)
            else:
                assert res[prop] is None
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


@mark.parametrize(
    "token_transfer_method, expected_transfer_method, cookies, headers",
    [
        ("any", "header", {}, {}),  # default
        ("header", "header", {"sAccessToken": EXAMPLE_JWT}, {}),  # specified
        ("cookie", "cookie", {}, {}),  #  specified
        (
            "cookie",
            "cookie",
            {},
            {"Authorization": f"Bearer {EXAMPLE_JWT}"},
        ),  #  specified
    ],
)
async def test_should_follow_get_token_transfer_method(
    app: TestClient,
    token_transfer_method: Union[TokenTransferMethod, Literal["any"]],
    expected_transfer_method: TokenTransferMethod,
    cookies: Dict[str, Any],
    headers: Dict[str, Any],
):
    init(
        **get_st_init_args(
            [
                session.init(
                    anti_csrf="VIA_TOKEN",
                    get_token_transfer_method=lambda _, __, ___: token_transfer_method,  # type: ignore
                )
            ]
        )
    )  # type:ignore
    start_st()

    res = create_session(app, None, None, cookies=cookies, headers=headers)

    passed_different_token = (len(cookies) != 0) or (len(headers) != 0)
    check_extracted_info(res, expected_transfer_method, passed_different_token)

    if len(cookies) != 0 and expected_transfer_method == "header":
        assert res["sAccessToken"]["value"] == ""
        assert res["sAccessToken"]["expires"] == "Thu, 01 Jan 1970 00:00:00 GMT"
        assert res["sRefreshToken"]["value"] == ""
        assert res["sRefreshToken"]["expires"] == "Thu, 01 Jan 1970 00:00:00 GMT"

    if len(headers) != 0 and expected_transfer_method == "cookie":
        assert res["accessTokenFromHeader"] == ""
        assert res["refreshTokenFromHeader"] == ""


@mark.parametrize(
    "transfer_method, session_required, auth_header, auth_cookie, result",
    [
        ("any", False, False, False, None),
        ("header", False, False, False, None),
        ("cookie", False, False, False, None),
        ("cookie", False, True, False, None),
        ("header", False, False, True, None),
        ("any", True, False, False, "UNAUTHORISED"),
        ("header", True, False, False, "UNAUTHORISED"),
        ("cookie", True, False, False, "UNAUTHORISED"),
        ("cookie", True, True, False, "UNAUTHORISED"),
        ("header", True, False, True, "UNAUTHORISED"),
        ("any", True, True, True, "validateheader"),
        ("any", False, True, True, "validateheader"),
        ("header", True, True, True, "validateheader"),
        ("header", False, True, True, "validateheader"),
        ("cookie", True, True, True, "validatecookie"),
        ("cookie", False, True, True, "validatecookie"),
        ("any", True, True, False, "validateheader"),
        ("any", False, True, False, "validateheader"),
        ("header", True, True, False, "validateheader"),
        ("header", False, True, False, "validateheader"),
        ("any", True, False, True, "validatecookie"),
        ("any", False, False, True, "validatecookie"),
        ("cookie", True, False, True, "validatecookie"),
        ("cookie", False, False, True, "validatecookie"),
    ],
)
def test_verify_session_parametrized(  # from behaviour table
    app: TestClient,
    transfer_method: TokenTransferMethod,  # transfer method for session recipe config
    session_required: bool,  # if session is required for verify session
    auth_header: bool,
    auth_cookie: bool,
    result: Optional[str],
):
    init(
        **get_st_init_args(
            [
                session.init(
                    anti_csrf="VIA_TOKEN",
                    get_token_transfer_method=lambda _, __, ___: transfer_method,
                )
            ]
        )
    )
    start_st()

    create_session_info = create_session(app, "cookie")

    # if use_expired_token:
    #     delay(3)

    auth_mode = "none"
    if auth_cookie and auth_header:
        auth_mode = "both"
    elif auth_header:
        auth_mode = "header"
    elif auth_cookie:
        auth_mode = "cookie"

    res = call_api(
        app,
        create_session_info,
        "/verify" if session_required else "/verify-optional",
        401 if result == "UNAUTHORISED" else 200,
        auth_mode,
    )
    assert res.status_code == (401 if result == "UNAUTHORISED" else 200)

    body = res.json()

    if result is None:
        assert body["sessionExists"] is False
    if result == "UNAUTHORISED":
        assert body["message"] == "unauthorised"
    if result in ("validateCookie", "validateHeader"):
        assert body["sessionExists"] is True


# # Skipping the following 3 tests as they are covered by previous tests:
# # Provide access token via both header and cookie. It should use the value from headers if getTokenTransferMethod returns header or any. If returns cookie, it should use the value from cookie.


async def test_should_reject_requests_with_sIdRefreshToken(app: TestClient):
    init(**get_st_init_args([session.init(anti_csrf="VIA_TOKEN")]))
    start_st()

    res = create_session(
        app,
        "cookie",
        None,
    )

    response = app.get(
        url="/verify",
        cookies={
            "sIdRefreshToken": "IRRELEVANT-VALUE",
            "sAccessToken": EXAMPLE_JWT,
        },
        headers={"anti-csrf": res["antiCsrf"]},
    )

    info = extract_info(response)

    assert response.status_code == 401
    assert response.json() == {"message": "try refresh token"}

    print(info)

    assert (
        "sIdRefreshToken" not in info
    )  # Doesn't clear sIdRefreshToken from cookies in get_session (called by verify_session)


# # SKIPPING:
# # with non ST in Authorize header
# # should use the value from cookies if present and getTokenTransferMethod returns {any,header,cookie}


# # merge_into_access_token_payload


@mark.parametrize("transfer_method", ["header", "cookie"])
async def test_should_update_acccess_token_payload(
    app: TestClient, transfer_method: str
):
    init(**get_st_init_args([session.init(anti_csrf="VIA_TOKEN")]))
    start_st()

    res = create_session(app, transfer_method)

    update_info = extract_info(
        call_api(app, res, "/update-payload", 200, "cookie", None)
    )

    # Didn't update
    assert update_info["refreshToken"] is None
    assert update_info["antiCsrf"] is None
    assert update_info["accessTokenFromHeader"] is None
    assert update_info["refreshTokenFromHeader"] is None

    # Updated access token
    assert update_info["accessToken"] is not None
    assert update_info["accessToken"] != res["accessTokenFromHeader"]
    # Updated front token
    assert update_info["frontToken"] is not None
    assert update_info["frontToken"] != res["frontToken"]


# refresh_session


@mark.parametrize(
    "transfer_method, auth_header, auth_cookie, output, set_tokens, cleared_tokens",
    [
        ("any", False, False, "unauthorised", None, None),
        ("header", False, False, "unauthorised", None, None),
        ("cookie", False, False, "unauthorised", None, None),
        ("any", False, True, "validatecookie", "cookies", None),
        ("header", False, True, "unauthorised", None, None),
        ("cookie", False, True, "validatecookie", "cookies", None),
        ("any", True, False, "validateheader", "headers", None),
        ("header", True, False, "validateheader", "headers", None),
        ("cookie", True, False, "unauthorised", None, None),
        ("any", True, True, "validateheader", "headers", "cookies"),
        ("header", True, True, "validateheader", "headers", "cookies"),
        ("cookie", True, True, "validatecookie", "cookies", "headers"),
    ],
)
async def test_refresh_session_parametrized(
    app: TestClient,
    transfer_method: TokenTransferMethod,
    auth_header: bool,
    auth_cookie: bool,
    output: Optional[str],
    set_tokens: Optional[str],
    cleared_tokens: Optional[str],
):
    init(
        **get_st_init_args(
            [
                session.init(
                    anti_csrf="VIA_TOKEN",
                    get_token_transfer_method=lambda _, __, ___: transfer_method,
                )
            ]
        )
    )
    start_st()

    # Token transfer method doesn't matter for this test
    res = create_session(app, "cookies")

    auth_mode = "none"
    if auth_cookie and auth_header:
        auth_mode = "both"
    elif auth_header:
        auth_mode = "header"
    elif auth_cookie:
        auth_mode = "cookie"

    refresh_result = extract_info(
        await refresh_session(app, transfer_method, auth_mode, res)
    )

    if output == "unauthorised":
        assert refresh_result["status_code"] == 401
        assert refresh_result["body"] == {"message": "unauthorised"}
    else:
        assert refresh_result["status_code"] == 200

    if cleared_tokens == "headers":
        assert refresh_result["accessTokenFromHeader"] == ""
        assert refresh_result["refreshTokenFromHeader"] == ""
    elif cleared_tokens == "cookies":
        assert refresh_result["accessToken"] == ""
        assert (
            refresh_result["sAccessToken"]["expires"] == "Thu, 01 Jan 1970 00:00:00 GMT"
        )
        assert refresh_result["refreshToken"] == ""
        assert (
            refresh_result["sRefreshToken"]["expires"]
            == "Thu, 01 Jan 1970 00:00:00 GMT"
        )

    if set_tokens == "headers":
        assert refresh_result["accessTokenFromHeader"] != ""
        assert refresh_result["refreshTokenFromHeader"] != ""
    elif set_tokens == "cookies":
        assert refresh_result["sAccessToken"]["value"] != ""
        assert (
            refresh_result["sAccessToken"]["expires"] != "Thu, 01 Jan 1970 00:00:00 GMT"
        )
        assert refresh_result["sRefreshToken"]["value"] != ""
        assert (
            refresh_result["sRefreshToken"]["expires"]
            != "Thu, 01 Jan 1970 00:00:00 GMT"
        )
    elif set_tokens is None:
        if cleared_tokens is None:
            assert refresh_result["frontToken"] is None
        return
    else:
        assert False, "Invalid set_tokens value"

    if set_tokens != "cookies" and cleared_tokens != "cookies":
        assert refresh_result["accessToken"] is None
        assert refresh_result["refreshToken"] is None
    elif set_tokens != "headers" and cleared_tokens != "headers":
        assert refresh_result["accessTokenFromHeader"] is None
        assert refresh_result["refreshTokenFromHeader"] is None


async def refresh_session(
    app: TestClient,
    auth_mode_header: TokenTransferMethod,
    auth_mode: str,
    res: Dict[str, str],
):
    headers = {}
    cookies = {}

    app.cookies = RequestsCookieJar()  # Reset cookies

    if auth_mode_header:
        headers["st-auth-mode"] = auth_mode_header

    access_token = res["accessToken"] or res["accessTokenFromHeader"]
    refresh_token = res["refreshToken"] or res["refreshTokenFromHeader"]

    if auth_mode in ("both", "cookie"):
        cookies["sAccessToken"] = access_token
        cookies["sRefreshToken"] = refresh_token
        if res.get("antiCsrf"):
            headers["anti-csrf"] = res["antiCsrf"]

    if auth_mode in ("both", "header"):
        headers["authorization"] = f"Bearer {refresh_token}"

    return app.post("/auth/session/refresh", headers=headers, cookies=cookies)
