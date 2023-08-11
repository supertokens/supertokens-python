# Copyright (c) 2021, VRAI Labs and/or its affiliates. All rights reserved.
#
# This software is licensed under the Apache License, Version 2.0 (the
# "License") as published by the Apache Software Foundation.
#
# You may not use this file except in compliance with the License. You may
# obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
import json
from typing import Any, Dict, Union

from fastapi import Depends, FastAPI
from fastapi.requests import Request
from fastapi.testclient import TestClient
from pytest import fixture, mark, skip
from supertokens_python import InputAppInfo, SupertokensConfig, init
from supertokens_python.framework.fastapi import get_middleware
from supertokens_python.recipe import emailpassword, session
from supertokens_python.recipe.emailpassword.interfaces import (
    APIInterface as EPAPIInterface,
)
from supertokens_python.recipe.emailpassword.interfaces import APIOptions
from supertokens_python.recipe.session import SessionContainer
from supertokens_python.recipe.session.asyncio import (
    create_new_session,
    get_session,
    refresh_session,
)
from supertokens_python.recipe.session.exceptions import UnauthorisedError
from supertokens_python.recipe.session.framework.fastapi import verify_session
from supertokens_python.recipe.session.interfaces import APIInterface
from supertokens_python.recipe.session.interfaces import APIOptions as SessionAPIOptions
from tests.utils import (
    TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH,
    TEST_DRIVER_CONFIG_COOKIE_DOMAIN,
    TEST_DRIVER_CONFIG_COOKIE_SAME_SITE,
    TEST_DRIVER_CONFIG_REFRESH_TOKEN_PATH,
    assert_info_clears_tokens,
    clean_st,
    extract_all_cookies,
    extract_info,
    get_st_init_args,
    reset,
    setup_st,
    start_st,
    create_users,
)
from supertokens_python.recipe.dashboard import DashboardRecipe, InputOverrideConfig
from supertokens_python.recipe.dashboard.interfaces import RecipeInterface
from supertokens_python.framework import BaseRequest
from supertokens_python.querier import Querier
from supertokens_python.utils import is_version_gte
from supertokens_python.recipe.passwordless import PasswordlessRecipe, ContactConfig
from supertokens_python.recipe import thirdparty

from supertokens_python.recipe.dashboard.utils import DashboardConfig


def override_dashboard_functions(original_implementation: RecipeInterface):
    async def should_allow_access(
        request: BaseRequest, __: DashboardConfig, ___: Dict[str, Any]
    ):
        auth_header = request.get_header("authorization")
        return auth_header == "Bearer testapikey"

    original_implementation.should_allow_access = should_allow_access  # type: ignore
    return original_implementation


def setup_function(_):
    reset()
    clean_st()
    setup_st()


def teardown_function(_):
    reset()
    clean_st()


@fixture(scope="function")
async def driver_config_client():
    app = FastAPI()
    app.add_middleware(get_middleware())

    @app.get("/login")
    async def login(request: Request):  # type: ignore
        user_id = "userId"
        await create_new_session(request, "public", user_id, {}, {})
        return {"userId": user_id}

    @app.post("/refresh")
    async def custom_refresh(request: Request):  # type: ignore
        await refresh_session(request)
        return {}  # type: ignore

    @app.get("/info")
    async def info_get(request: Request):  # type: ignore
        await get_session(request, True)
        return {}  # type: ignore

    @app.get("/custom/info")
    def custom_info(_):  # type: ignore
        return {}  # type: ignore

    @app.options("/custom/handle")
    def custom_handle_options(_):  # type: ignore
        return {"method": "option"}

    @app.get("/handle")
    async def handle_get(request: Request):  # type: ignore
        session: Union[None, SessionContainer] = await get_session(request, True)
        if session is None:
            raise Exception("Should never come here")
        return {"s": session.get_handle()}

    @app.get("/handle-session-optional")
    async def handle_get_optional(session: SessionContainer = Depends(verify_session(session_required=False))):  # type: ignore
        if session is None:
            return {"s": "empty session"}
        return {"s": session.get_handle()}

    @app.post("/logout")
    async def custom_logout(request: Request):  # type: ignore
        session: Union[None, SessionContainer] = await get_session(request, True)
        if session is None:
            raise Exception("Should never come here")
        await session.revoke_session()
        return {}  # type: ignore

    @app.post("/create")
    async def _create(request: Request):  # type: ignore
        await create_new_session(request, "public", "userId", {}, {})
        return ""

    @app.post("/create-throw")
    async def _create_throw(request: Request):  # type: ignore
        await create_new_session(request, "public", "userId", {}, {})
        raise UnauthorisedError("unauthorised")

    return TestClient(app)


def apis_override_session(param: APIInterface):
    param.disable_refresh_post = True
    return param


@mark.asyncio
async def test_login_refresh(driver_config_client: TestClient):
    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth",
        ),
        framework="fastapi",
        recipe_list=[
            session.init(
                anti_csrf="VIA_TOKEN",
                cookie_domain="supertokens.io",
                get_token_transfer_method=lambda _, __, ___: "cookie",
                override=session.InputOverrideConfig(apis=apis_override_session),
            )
        ],
    )
    start_st()

    response_1 = driver_config_client.get("/login")
    cookies_1 = extract_all_cookies(response_1)

    assert response_1.headers.get("anti-csrf") is not None
    assert cookies_1["sAccessToken"]["domain"] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_1["sRefreshToken"]["domain"] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_1["sAccessToken"]["path"] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
    assert cookies_1["sRefreshToken"]["path"] == TEST_DRIVER_CONFIG_REFRESH_TOKEN_PATH
    assert cookies_1["sAccessToken"]["httponly"]
    assert cookies_1["sRefreshToken"]["httponly"]
    assert (
        cookies_1["sAccessToken"]["samesite"].lower()
        == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    )
    assert (
        cookies_1["sRefreshToken"]["samesite"].lower()
        == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    )

    response_3 = driver_config_client.post(
        url="/refresh",
        headers={"anti-csrf": response_1.headers.get("anti-csrf")},
        cookies={
            "sRefreshToken": cookies_1["sRefreshToken"]["value"],
        },
    )
    cookies_3 = extract_all_cookies(response_3)

    assert cookies_3["sAccessToken"]["value"] != cookies_1["sAccessToken"]["value"]
    assert cookies_3["sRefreshToken"]["value"] != cookies_1["sRefreshToken"]["value"]
    assert response_3.headers.get("anti-csrf") is not None
    assert cookies_3["sAccessToken"]["domain"] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_3["sRefreshToken"]["domain"] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_3["sRefreshToken"]["path"] == TEST_DRIVER_CONFIG_REFRESH_TOKEN_PATH
    assert cookies_3["sAccessToken"]["httponly"]
    assert cookies_3["sRefreshToken"]["httponly"]
    assert (
        cookies_3["sAccessToken"]["samesite"].lower()
        == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    )
    assert (
        cookies_3["sRefreshToken"]["samesite"].lower()
        == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    )


@mark.asyncio
async def test_login_logout(driver_config_client: TestClient):
    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth",
        ),
        framework="fastapi",
        recipe_list=[
            session.init(
                anti_csrf="VIA_TOKEN",
                cookie_domain="supertokens.io",
                get_token_transfer_method=lambda _, __, ___: "cookie",
            )
        ],
    )
    start_st()

    response_1 = driver_config_client.get("/login")
    cookies_1 = extract_all_cookies(response_1)

    assert response_1.headers.get("anti-csrf") is not None
    assert cookies_1["sAccessToken"]["domain"] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_1["sRefreshToken"]["domain"] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_1["sAccessToken"]["path"] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
    assert cookies_1["sRefreshToken"]["path"] == TEST_DRIVER_CONFIG_REFRESH_TOKEN_PATH
    assert cookies_1["sAccessToken"]["httponly"]
    assert cookies_1["sRefreshToken"]["httponly"]
    assert (
        cookies_1["sAccessToken"]["samesite"].lower()
        == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    )
    assert (
        cookies_1["sRefreshToken"]["samesite"].lower()
        == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    )
    assert cookies_1["sAccessToken"]["secure"] is None
    assert cookies_1["sRefreshToken"]["secure"] is None

    response_2 = driver_config_client.post(
        url="/logout",
        headers={"anti-csrf": response_1.headers.get("anti-csrf")},
        cookies={
            "sAccessToken": cookies_1["sAccessToken"]["value"],
        },
    )
    cookies_2 = extract_all_cookies(response_2)
    assert response_2.headers.get("anti-csrf") is None
    assert cookies_2["sAccessToken"]["value"] == ""
    assert cookies_2["sRefreshToken"]["value"] == ""
    assert cookies_2["sAccessToken"]["domain"] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_2["sRefreshToken"]["domain"] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_2["sAccessToken"]["path"] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
    assert cookies_2["sAccessToken"]["httponly"]
    assert cookies_2["sRefreshToken"]["httponly"]
    assert (
        cookies_2["sAccessToken"]["samesite"].lower()
        == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    )
    assert (
        cookies_2["sRefreshToken"]["samesite"].lower()
        == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    )
    assert cookies_2["sAccessToken"]["secure"] is None
    assert cookies_2["sRefreshToken"]["secure"] is None


@mark.asyncio
async def test_login_info(driver_config_client: TestClient):
    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth",
        ),
        framework="fastapi",
        recipe_list=[
            session.init(
                anti_csrf="VIA_TOKEN",
                cookie_domain="supertokens.io",
                get_token_transfer_method=lambda _, __, ___: "cookie",
            )
        ],
    )
    start_st()

    response_1 = driver_config_client.get("/login")
    cookies_1 = extract_all_cookies(response_1)

    assert response_1.headers.get("anti-csrf") is not None
    assert cookies_1["sAccessToken"]["domain"] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_1["sRefreshToken"]["domain"] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_1["sAccessToken"]["path"] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
    assert cookies_1["sRefreshToken"]["path"] == TEST_DRIVER_CONFIG_REFRESH_TOKEN_PATH
    assert cookies_1["sAccessToken"]["httponly"]
    assert cookies_1["sRefreshToken"]["httponly"]
    assert (
        cookies_1["sAccessToken"]["samesite"].lower()
        == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    )
    assert (
        cookies_1["sRefreshToken"]["samesite"].lower()
        == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    )
    assert cookies_1["sAccessToken"]["secure"] is None
    assert cookies_1["sRefreshToken"]["secure"] is None

    response_2 = driver_config_client.get(
        url="/info",
        headers={"anti-csrf": response_1.headers.get("anti-csrf")},
        cookies={
            "sAccessToken": cookies_1["sAccessToken"]["value"],
        },
    )
    cookies_2 = extract_all_cookies(response_2)
    assert not cookies_2


@mark.asyncio
async def test_login_handle(driver_config_client: TestClient):
    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth",
        ),
        framework="fastapi",
        recipe_list=[
            session.init(
                anti_csrf="VIA_TOKEN",
                cookie_domain="supertokens.io",
                get_token_transfer_method=lambda _, __, ___: "cookie",
            )
        ],
    )
    start_st()

    response_1 = driver_config_client.get("/login")
    cookies_1 = extract_all_cookies(response_1)

    assert response_1.headers.get("anti-csrf") is not None
    assert cookies_1["sAccessToken"]["domain"] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_1["sRefreshToken"]["domain"] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_1["sAccessToken"]["path"] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
    assert cookies_1["sRefreshToken"]["path"] == TEST_DRIVER_CONFIG_REFRESH_TOKEN_PATH
    assert cookies_1["sAccessToken"]["httponly"]
    assert cookies_1["sRefreshToken"]["httponly"]
    assert (
        cookies_1["sAccessToken"]["samesite"].lower()
        == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    )
    assert (
        cookies_1["sRefreshToken"]["samesite"].lower()
        == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    )
    assert cookies_1["sAccessToken"]["secure"] is None
    assert cookies_1["sRefreshToken"]["secure"] is None

    response_2 = driver_config_client.get(
        url="/handle",
        headers={"anti-csrf": response_1.headers.get("anti-csrf")},
        cookies={
            "sAccessToken": cookies_1["sAccessToken"]["value"],
        },
    )
    result_dict = json.loads(response_2.content)
    assert "s" in result_dict


@mark.asyncio
async def test_login_refresh_error_handler(driver_config_client: TestClient):
    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth",
        ),
        framework="fastapi",
        recipe_list=[
            session.init(
                anti_csrf="VIA_TOKEN",
                cookie_domain="supertokens.io",
                get_token_transfer_method=lambda _, __, ___: "cookie",
            )
        ],
    )
    start_st()

    response_1 = driver_config_client.get("/login")
    cookies_1 = extract_all_cookies(response_1)

    assert response_1.headers.get("anti-csrf") is not None
    assert cookies_1["sAccessToken"]["domain"] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_1["sRefreshToken"]["domain"] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_1["sAccessToken"]["path"] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
    assert cookies_1["sRefreshToken"]["path"] == TEST_DRIVER_CONFIG_REFRESH_TOKEN_PATH
    assert cookies_1["sAccessToken"]["httponly"]
    assert cookies_1["sRefreshToken"]["httponly"]
    assert (
        cookies_1["sAccessToken"]["samesite"].lower()
        == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    )
    assert (
        cookies_1["sRefreshToken"]["samesite"].lower()
        == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    )
    assert cookies_1["sAccessToken"]["secure"] is None
    assert cookies_1["sRefreshToken"]["secure"] is None

    response_3 = driver_config_client.post(
        url="/refresh",
        headers={"anti-csrf": response_1.headers.get("anti-csrf")},
        cookies={
            # no cookies
        },
    )
    assert response_3.status_code == 401  # not authorized because no refresh tokens


@mark.asyncio
async def test_custom_response(driver_config_client: TestClient):
    def override_email_password_apis(original_implementation: EPAPIInterface):

        original_func = original_implementation.email_exists_get

        async def email_exists_get(
            email: str,
            tenant_id: str,
            api_options: APIOptions,
            user_context: Dict[str, Any],
        ):
            response_dict = {"custom": True}
            api_options.response.set_status_code(203)
            api_options.response.set_json_content(response_dict)
            return await original_func(email, tenant_id, api_options, user_context)

        original_implementation.email_exists_get = email_exists_get
        return original_implementation

    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth",
        ),
        framework="fastapi",
        recipe_list=[
            emailpassword.init(
                override=emailpassword.InputOverrideConfig(
                    apis=override_email_password_apis
                )
            )
        ],
    )
    start_st()

    response = driver_config_client.get(
        url="/auth/signup/email/exists?email=test@example.com",
    )

    dict_response = json.loads(response.text)
    assert response.status_code == 203
    assert dict_response["custom"]


@mark.asyncio
async def test_optional_session(driver_config_client: TestClient):

    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth",
        ),
        framework="fastapi",
        recipe_list=[
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie")
        ],
    )
    start_st()

    response = driver_config_client.get(
        url="handle-session-optional",
    )

    dict_response = json.loads(response.text)
    assert response.status_code == 200
    assert dict_response["s"] == "empty session"


@mark.parametrize(
    "fastapi_root_path",
    [
        "/api/v1",
        "/api",
        "api",
        # Don't pass "/" as fastapi_root_path. You'll get unexpected behaviour
        # because api_base_path will be "//auth"
    ],
)
def test_fastapi_root_path(fastapi_root_path: str):
    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path=f"{fastapi_root_path}/auth",  # It's important to prepend the root path here
        ),
        framework="fastapi",
        recipe_list=[
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
            emailpassword.init(),
        ],
    )
    start_st()

    # Test with root_path
    app = FastAPI(root_path=fastapi_root_path)
    app.add_middleware(get_middleware())
    test_client = TestClient(app)

    response = test_client.get(
        f"{fastapi_root_path}/auth/signup/email/exists?email=test@example.com"
    )
    assert response.status_code == 200
    assert response.json() == {"status": "OK", "exists": False}

    # The API should migrate (and return 404 here)
    response = test_client.get("/auth/signup/email/exists?email=test@example.com")
    assert response.status_code == 404


@mark.asyncio
@mark.parametrize("token_transfer_method", ["cookie", "header"])
async def test_should_clear_all_response_during_refresh_if_unauthorized(
    driver_config_client: TestClient, token_transfer_method: str
):
    def override_session_apis(oi: APIInterface):
        oi_refresh_post = oi.refresh_post

        async def refresh_post(
            api_options: SessionAPIOptions, user_context: Dict[str, Any]
        ):
            await oi_refresh_post(api_options, user_context)
            raise UnauthorisedError("unauthorized", clear_tokens=True)

        oi.refresh_post = refresh_post
        return oi

    init(
        **get_st_init_args(
            [
                session.init(
                    anti_csrf="VIA_TOKEN",
                    override=session.InputOverrideConfig(apis=override_session_apis),
                )
            ]
        )
    )  # type: ignore
    start_st()

    res = driver_config_client.post(
        "/create", headers={"st-auth-mode": token_transfer_method}
    )
    info = extract_info(res)

    assert info["accessTokenFromAny"] is not None
    assert info["refreshTokenFromAny"] is not None

    headers: Dict[str, Any] = {}
    cookies: Dict[str, Any] = {}

    if token_transfer_method == "header":
        headers.update({"authorization": f"Bearer {info['refreshTokenFromAny']}"})
    else:
        cookies.update(
            {"sRefreshToken": info["refreshTokenFromAny"], "sIdRefreshToken": "asdf"}
        )

    if info["antiCsrf"] is not None:
        headers.update({"anti-csrf": info["antiCsrf"]})

    res = driver_config_client.post(
        "/auth/session/refresh", headers=headers, cookies=cookies
    )
    info = extract_info(res)

    assert res.status_code == 401
    assert_info_clears_tokens(info, token_transfer_method)


@mark.asyncio
@mark.parametrize("token_transfer_method", ["cookie", "header"])
async def test_revoking_session_after_create_new_session_with_throwing_unauthorized_error(
    driver_config_client: TestClient, token_transfer_method: str
):
    init(
        **get_st_init_args(
            [
                session.init(
                    anti_csrf="VIA_TOKEN",
                )
            ]
        )
    )  # type: ignore
    start_st()

    res = driver_config_client.post(
        "/create-throw", headers={"st-auth-mode": token_transfer_method}
    )
    info = extract_info(res)

    assert res.status_code == 401
    assert_info_clears_tokens(info, token_transfer_method)


@mark.asyncio
async def test_session_with_legacy_refresh_token_and_unauthorized_should_clear_legacy_token(
    driver_config_client: TestClient,
):
    init(
        **get_st_init_args(
            [
                session.init(
                    anti_csrf="VIA_TOKEN",
                )
            ]
        )
    )  # type: ignore
    start_st()

    headers: Dict[str, Any] = {}
    cookies: Dict[str, Any] = {}

    cookies.update(
        # Invalid refresh token so that core throws an unauthorized error
        {"sRefreshToken": "non-existing-token", "sIdRefreshToken": "irrelevant-value"}
    )

    res = driver_config_client.post(
        "/auth/session/refresh", headers=headers, cookies=cookies
    )
    info = extract_info(res)

    assert res.status_code == 401
    assert res.json() == {"message": "unauthorised"}
    assert_info_clears_tokens(info, "cookie")

    assert info["sIdRefreshToken"]["value"] == ""
    assert info["sIdRefreshToken"]["expires"] == "Thu, 01 Jan 1970 00:00:00 GMT"


@mark.asyncio
async def test_search_with_email_t(driver_config_client: TestClient):
    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth",
        ),
        framework="flask",
        recipe_list=[
            session.init(
                anti_csrf="VIA_TOKEN",
                cookie_domain="supertokens.io",
                get_token_transfer_method=lambda _, __, ___: "cookie",
            ),
            DashboardRecipe.init(
                api_key="testapikey",
                override=InputOverrideConfig(functions=override_dashboard_functions),
            ),
            emailpassword.init(),
        ],
    )
    start_st()
    querier = Querier.get_instance(DashboardRecipe.recipe_id)
    cdi_version = await querier.get_api_version()
    if not cdi_version:
        skip()
    if not is_version_gte(cdi_version, "2.20"):
        skip()
    await create_users(emailpassword=True)
    query = {"limit": "10", "email": "t"}
    res = driver_config_client.get(
        "/auth/dashboard/api/users",
        headers={
            "Authorization": "Bearer testapikey",
            "Content-Type": "application/json",
        },
        params=query,
    )
    info = extract_info(res)
    assert res.status_code == 200
    assert len(info["body"]["users"]) == 5


@mark.asyncio
async def test_search_with_email_multiple_email_entry(driver_config_client: TestClient):
    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth",
        ),
        framework="flask",
        recipe_list=[
            session.init(
                anti_csrf="VIA_TOKEN",
                cookie_domain="supertokens.io",
                get_token_transfer_method=lambda _, __, ___: "cookie",
            ),
            DashboardRecipe.init(
                api_key="testapikey",
                override=InputOverrideConfig(functions=override_dashboard_functions),
            ),
            emailpassword.init(),
        ],
    )
    start_st()
    querier = Querier.get_instance(DashboardRecipe.recipe_id)
    cdi_version = await querier.get_api_version()
    if not cdi_version:
        skip()
    if not is_version_gte(cdi_version, "2.20"):
        skip()
    await create_users(emailpassword=True)
    query = {"limit": "10", "email": "iresh;john"}
    res = driver_config_client.get(
        "/auth/dashboard/api/users",
        headers={
            "Authorization": "Bearer testapikey",
            "Content-Type": "application/json",
        },
        params=query,
    )
    info = extract_info(res)
    assert res.status_code == 200
    assert len(info["body"]["users"]) == 1


@mark.asyncio
async def test_search_with_email_iresh(driver_config_client: TestClient):
    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth",
        ),
        framework="flask",
        recipe_list=[
            session.init(
                anti_csrf="VIA_TOKEN",
                cookie_domain="supertokens.io",
                get_token_transfer_method=lambda _, __, ___: "cookie",
            ),
            DashboardRecipe.init(
                api_key="testapikey",
                override=InputOverrideConfig(functions=override_dashboard_functions),
            ),
            emailpassword.init(),
        ],
    )
    start_st()
    querier = Querier.get_instance(DashboardRecipe.recipe_id)
    cdi_version = await querier.get_api_version()
    if not cdi_version:
        skip()
    if not is_version_gte(cdi_version, "2.20"):
        skip()
    await create_users(emailpassword=True)
    query = {"limit": "10", "email": "iresh"}
    res = driver_config_client.get(
        "/auth/dashboard/api/users",
        headers={
            "Authorization": "Bearer testapikey",
            "Content-Type": "application/json",
        },
        params=query,
    )
    info = extract_info(res)
    assert res.status_code == 200
    assert len(info["body"]["users"]) == 0


@mark.asyncio
async def test_search_with_phone_plus_one(driver_config_client: TestClient):
    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth",
        ),
        framework="flask",
        recipe_list=[
            session.init(
                anti_csrf="VIA_TOKEN",
                cookie_domain="supertokens.io",
                get_token_transfer_method=lambda _, __, ___: "cookie",
            ),
            DashboardRecipe.init(
                api_key="testapikey",
                override=InputOverrideConfig(functions=override_dashboard_functions),
            ),
            PasswordlessRecipe.init(
                contact_config=ContactConfig(contact_method="EMAIL"),
                flow_type="USER_INPUT_CODE",
            ),
        ],
    )
    start_st()
    querier = Querier.get_instance(DashboardRecipe.recipe_id)
    cdi_version = await querier.get_api_version()
    if not cdi_version:
        skip()
    if not is_version_gte(cdi_version, "2.20"):
        skip()
    await create_users(passwordless=True)
    query = {"limit": "10", "phone": "+1"}
    res = driver_config_client.get(
        "/auth/dashboard/api/users",
        headers={
            "Authorization": "Bearer testapikey",
            "Content-Type": "application/json",
        },
        params=query,
    )
    info = extract_info(res)
    assert res.status_code == 200
    assert len(info["body"]["users"]) == 3


@mark.asyncio
async def test_search_with_phone_one_bracket(driver_config_client: TestClient):
    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth",
        ),
        framework="flask",
        recipe_list=[
            session.init(
                anti_csrf="VIA_TOKEN",
                cookie_domain="supertokens.io",
                get_token_transfer_method=lambda _, __, ___: "cookie",
            ),
            DashboardRecipe.init(
                api_key="testapikey",
                override=InputOverrideConfig(functions=override_dashboard_functions),
            ),
            PasswordlessRecipe.init(
                contact_config=ContactConfig(contact_method="EMAIL"),
                flow_type="USER_INPUT_CODE",
            ),
        ],
    )
    start_st()
    querier = Querier.get_instance(DashboardRecipe.recipe_id)
    cdi_version = await querier.get_api_version()
    if not cdi_version:
        skip()
    if not is_version_gte(cdi_version, "2.20"):
        skip()
    await create_users(passwordless=True)
    query = {"limit": "10", "phone": "1("}
    res = driver_config_client.get(
        "/auth/dashboard/api/users",
        headers={
            "Authorization": "Bearer testapikey",
            "Content-Type": "application/json",
        },
        params=query,
    )
    info = extract_info(res)
    assert res.status_code == 200
    assert len(info["body"]["users"]) == 0


@mark.asyncio
async def test_search_with_provider_google(driver_config_client: TestClient):
    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth",
        ),
        framework="flask",
        recipe_list=[
            session.init(
                anti_csrf="VIA_TOKEN",
                cookie_domain="supertokens.io",
                get_token_transfer_method=lambda _, __, ___: "cookie",
            ),
            DashboardRecipe.init(
                api_key="testapikey",
                override=InputOverrideConfig(functions=override_dashboard_functions),
            ),
            thirdparty.init(
                sign_in_and_up_feature=thirdparty.SignInAndUpFeature(
                    providers=[
                        thirdparty.ProviderInput(
                            config=thirdparty.ProviderConfig(
                                third_party_id="apple",
                                clients=[
                                    thirdparty.ProviderClientConfig(
                                        client_id="4398792-io.supertokens.example.service",
                                        additional_config={
                                            "keyId": "7M48Y4RYDL",
                                            "teamId": "YWQCXGJRJL",
                                            "privateKey": "-----BEGIN PRIVATE KEY-----\nMIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgu8gXs+XYkqXD6Ala9Sf/iJXzhbwcoG5dMh1OonpdJUmgCgYIKoZIzj0DAQehRANCAASfrvlFbFCYqn3I2zeknYXLwtH30JuOKestDbSfZYxZNMqhF/OzdZFTV0zc5u5s3eN+oCWbnvl0hM+9IW0UlkdA\n-----END PRIVATE KEY-----",
                                        },
                                    ),
                                ],
                            )
                        ),
                        thirdparty.ProviderInput(
                            config=thirdparty.ProviderConfig(
                                third_party_id="google",
                                clients=[
                                    thirdparty.ProviderClientConfig(
                                        client_id="467101b197249757c71f",
                                        client_secret="e97051221f4b6426e8fe8d51486396703012f5bd",
                                    ),
                                ],
                            )
                        ),
                        thirdparty.ProviderInput(
                            config=thirdparty.ProviderConfig(
                                third_party_id="github",
                                clients=[
                                    thirdparty.ProviderClientConfig(
                                        client_id="1060725074195-kmeum4crr01uirfl2op9kd5acmi9jutn.apps.googleusercontent.com",
                                        client_secret="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",
                                    ),
                                ],
                            )
                        ),
                    ],
                )
            ),
        ],
    )
    start_st()
    querier = Querier.get_instance(DashboardRecipe.recipe_id)
    cdi_version = await querier.get_api_version()
    if not cdi_version:
        skip()
    if not is_version_gte(cdi_version, "2.20"):
        skip()
    await create_users(thirdparty=True)
    query = {"limit": "10", "provider": "google"}
    res = driver_config_client.get(
        "/auth/dashboard/api/users",
        headers={
            "Authorization": "Bearer testapikey",
            "Content-Type": "application/json",
        },
        params=query,
    )
    info = extract_info(res)
    assert res.status_code == 200
    assert len(info["body"]["users"]) == 3


@mark.asyncio
async def test_search_with_provider_google_and_phone_1(
    driver_config_client: TestClient,
):
    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth",
        ),
        framework="flask",
        recipe_list=[
            session.init(
                anti_csrf="VIA_TOKEN",
                cookie_domain="supertokens.io",
                get_token_transfer_method=lambda _, __, ___: "cookie",
            ),
            DashboardRecipe.init(
                api_key="testapikey",
                override=InputOverrideConfig(functions=override_dashboard_functions),
            ),
            PasswordlessRecipe.init(
                contact_config=ContactConfig(contact_method="EMAIL"),
                flow_type="USER_INPUT_CODE",
            ),
            thirdparty.init(
                sign_in_and_up_feature=thirdparty.SignInAndUpFeature(
                    providers=[
                        thirdparty.ProviderInput(
                            config=thirdparty.ProviderConfig(
                                third_party_id="apple",
                                clients=[
                                    thirdparty.ProviderClientConfig(
                                        client_id="4398792-io.supertokens.example.service",
                                        additional_config={
                                            "keyId": "7M48Y4RYDL",
                                            "teamId": "YWQCXGJRJL",
                                            "privateKey": "-----BEGIN PRIVATE KEY-----\nMIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgu8gXs+XYkqXD6Ala9Sf/iJXzhbwcoG5dMh1OonpdJUmgCgYIKoZIzj0DAQehRANCAASfrvlFbFCYqn3I2zeknYXLwtH30JuOKestDbSfZYxZNMqhF/OzdZFTV0zc5u5s3eN+oCWbnvl0hM+9IW0UlkdA\n-----END PRIVATE KEY-----",
                                        },
                                    ),
                                ],
                            )
                        ),
                        thirdparty.ProviderInput(
                            config=thirdparty.ProviderConfig(
                                third_party_id="google",
                                clients=[
                                    thirdparty.ProviderClientConfig(
                                        client_id="467101b197249757c71f",
                                        client_secret="e97051221f4b6426e8fe8d51486396703012f5bd",
                                    ),
                                ],
                            )
                        ),
                        thirdparty.ProviderInput(
                            config=thirdparty.ProviderConfig(
                                third_party_id="github",
                                clients=[
                                    thirdparty.ProviderClientConfig(
                                        client_id="1060725074195-kmeum4crr01uirfl2op9kd5acmi9jutn.apps.googleusercontent.com",
                                        client_secret="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",
                                    ),
                                ],
                            )
                        ),
                    ],
                )
            ),
        ],
    )
    start_st()
    querier = Querier.get_instance(DashboardRecipe.recipe_id)
    cdi_version = await querier.get_api_version()
    if not cdi_version:
        skip()
    if not is_version_gte(cdi_version, "2.20"):
        skip()
    await create_users(thirdparty=True, passwordless=True)
    query = {"limit": "10", "provider": "google", "phone": "1"}
    res = driver_config_client.get(
        "/auth/dashboard/api/users",
        headers={
            "Authorization": "Bearer testapikey",
            "Content-Type": "application/json",
        },
        params=query,
    )
    info = extract_info(res)
    assert res.status_code == 200
    assert len(info["body"]["users"]) == 0
