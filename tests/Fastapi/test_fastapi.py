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
from pytest import fixture, mark
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
from supertokens_python.recipe.session.framework.fastapi import verify_session
from supertokens_python.recipe.session.interfaces import APIInterface
from tests.utils import (
    TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH,
    TEST_DRIVER_CONFIG_COOKIE_DOMAIN,
    TEST_DRIVER_CONFIG_COOKIE_SAME_SITE,
    TEST_DRIVER_CONFIG_REFRESH_TOKEN_PATH,
    clean_st,
    extract_all_cookies,
    reset,
    setup_st,
    start_st,
)


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
        await create_new_session(request, user_id, {}, {})
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
    assert cookies_1["sIdRefreshToken"]["domain"] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_1["sAccessToken"]["path"] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
    assert cookies_1["sRefreshToken"]["path"] == TEST_DRIVER_CONFIG_REFRESH_TOKEN_PATH
    assert cookies_1["sIdRefreshToken"]["path"] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
    assert cookies_1["sAccessToken"]["httponly"]
    assert cookies_1["sRefreshToken"]["httponly"]
    assert cookies_1["sIdRefreshToken"]["httponly"]
    assert (
        cookies_1["sAccessToken"]["samesite"].lower()
        == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    )
    assert (
        cookies_1["sRefreshToken"]["samesite"].lower()
        == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    )
    assert (
        cookies_1["sIdRefreshToken"]["samesite"].lower()
        == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    )

    response_3 = driver_config_client.post(
        url="/refresh",
        headers={"anti-csrf": response_1.headers.get("anti-csrf")},
        cookies={
            "sRefreshToken": cookies_1["sRefreshToken"]["value"],
            "sIdRefreshToken": cookies_1["sIdRefreshToken"]["value"],
        },
    )
    cookies_3 = extract_all_cookies(response_3)

    assert cookies_3["sAccessToken"]["value"] != cookies_1["sAccessToken"]["value"]
    assert cookies_3["sRefreshToken"]["value"] != cookies_1["sRefreshToken"]["value"]
    assert (
        cookies_3["sIdRefreshToken"]["value"] != cookies_1["sIdRefreshToken"]["value"]
    )
    assert response_3.headers.get("anti-csrf") is not None
    assert cookies_3["sAccessToken"]["domain"] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_3["sRefreshToken"]["domain"] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_3["sIdRefreshToken"]["domain"] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_3["sRefreshToken"]["path"] == TEST_DRIVER_CONFIG_REFRESH_TOKEN_PATH
    assert cookies_3["sIdRefreshToken"]["path"] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
    assert cookies_3["sAccessToken"]["httponly"]
    assert cookies_3["sRefreshToken"]["httponly"]
    assert cookies_3["sIdRefreshToken"]["httponly"]
    assert (
        cookies_3["sAccessToken"]["samesite"].lower()
        == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    )
    assert (
        cookies_3["sRefreshToken"]["samesite"].lower()
        == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    )
    assert (
        cookies_3["sIdRefreshToken"]["samesite"].lower()
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
            session.init(anti_csrf="VIA_TOKEN", cookie_domain="supertokens.io")
        ],
    )
    start_st()

    response_1 = driver_config_client.get("/login")
    cookies_1 = extract_all_cookies(response_1)

    assert response_1.headers.get("anti-csrf") is not None
    assert cookies_1["sAccessToken"]["domain"] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_1["sRefreshToken"]["domain"] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_1["sIdRefreshToken"]["domain"] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_1["sAccessToken"]["path"] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
    assert cookies_1["sRefreshToken"]["path"] == TEST_DRIVER_CONFIG_REFRESH_TOKEN_PATH
    assert cookies_1["sIdRefreshToken"]["path"] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
    assert cookies_1["sAccessToken"]["httponly"]
    assert cookies_1["sRefreshToken"]["httponly"]
    assert cookies_1["sIdRefreshToken"]["httponly"]
    assert (
        cookies_1["sAccessToken"]["samesite"].lower()
        == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    )
    assert (
        cookies_1["sRefreshToken"]["samesite"].lower()
        == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    )
    assert (
        cookies_1["sIdRefreshToken"]["samesite"].lower()
        == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    )
    assert cookies_1["sAccessToken"]["secure"] is None
    assert cookies_1["sRefreshToken"]["secure"] is None
    assert cookies_1["sIdRefreshToken"]["secure"] is None

    response_2 = driver_config_client.post(
        url="/logout",
        headers={"anti-csrf": response_1.headers.get("anti-csrf")},
        cookies={
            "sAccessToken": cookies_1["sAccessToken"]["value"],
            "sIdRefreshToken": cookies_1["sIdRefreshToken"]["value"],
        },
    )
    cookies_2 = extract_all_cookies(response_2)
    assert response_2.headers.get("anti-csrf") is None
    assert cookies_2["sAccessToken"]["value"] == ""
    assert cookies_2["sRefreshToken"]["value"] == ""
    assert cookies_2["sIdRefreshToken"]["value"] == ""
    assert cookies_2["sAccessToken"]["domain"] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_2["sRefreshToken"]["domain"] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_2["sIdRefreshToken"]["domain"] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_2["sAccessToken"]["path"] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
    assert cookies_2["sAccessToken"]["httponly"]
    assert cookies_2["sRefreshToken"]["httponly"]
    assert cookies_2["sIdRefreshToken"]["httponly"]
    assert (
        cookies_2["sAccessToken"]["samesite"].lower()
        == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    )
    assert (
        cookies_2["sRefreshToken"]["samesite"].lower()
        == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    )
    assert (
        cookies_2["sIdRefreshToken"]["samesite"].lower()
        == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    )
    assert cookies_2["sAccessToken"]["secure"] is None
    assert cookies_2["sRefreshToken"]["secure"] is None
    assert cookies_2["sIdRefreshToken"]["secure"] is None


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
            session.init(anti_csrf="VIA_TOKEN", cookie_domain="supertokens.io")
        ],
    )
    start_st()

    response_1 = driver_config_client.get("/login")
    cookies_1 = extract_all_cookies(response_1)

    assert response_1.headers.get("anti-csrf") is not None
    assert cookies_1["sAccessToken"]["domain"] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_1["sRefreshToken"]["domain"] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_1["sIdRefreshToken"]["domain"] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_1["sAccessToken"]["path"] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
    assert cookies_1["sRefreshToken"]["path"] == TEST_DRIVER_CONFIG_REFRESH_TOKEN_PATH
    assert cookies_1["sIdRefreshToken"]["path"] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
    assert cookies_1["sAccessToken"]["httponly"]
    assert cookies_1["sRefreshToken"]["httponly"]
    assert cookies_1["sIdRefreshToken"]["httponly"]
    assert (
        cookies_1["sAccessToken"]["samesite"].lower()
        == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    )
    assert (
        cookies_1["sRefreshToken"]["samesite"].lower()
        == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    )
    assert (
        cookies_1["sIdRefreshToken"]["samesite"].lower()
        == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    )
    assert cookies_1["sAccessToken"]["secure"] is None
    assert cookies_1["sRefreshToken"]["secure"] is None
    assert cookies_1["sIdRefreshToken"]["secure"] is None

    response_2 = driver_config_client.get(
        url="/info",
        headers={"anti-csrf": response_1.headers.get("anti-csrf")},
        cookies={
            "sAccessToken": cookies_1["sAccessToken"]["value"],
            "sIdRefreshToken": cookies_1["sIdRefreshToken"]["value"],
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
            session.init(anti_csrf="VIA_TOKEN", cookie_domain="supertokens.io")
        ],
    )
    start_st()

    response_1 = driver_config_client.get("/login")
    cookies_1 = extract_all_cookies(response_1)

    assert response_1.headers.get("anti-csrf") is not None
    assert cookies_1["sAccessToken"]["domain"] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_1["sRefreshToken"]["domain"] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_1["sIdRefreshToken"]["domain"] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_1["sAccessToken"]["path"] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
    assert cookies_1["sRefreshToken"]["path"] == TEST_DRIVER_CONFIG_REFRESH_TOKEN_PATH
    assert cookies_1["sIdRefreshToken"]["path"] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
    assert cookies_1["sAccessToken"]["httponly"]
    assert cookies_1["sRefreshToken"]["httponly"]
    assert cookies_1["sIdRefreshToken"]["httponly"]
    assert (
        cookies_1["sAccessToken"]["samesite"].lower()
        == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    )
    assert (
        cookies_1["sRefreshToken"]["samesite"].lower()
        == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    )
    assert (
        cookies_1["sIdRefreshToken"]["samesite"].lower()
        == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    )
    assert cookies_1["sAccessToken"]["secure"] is None
    assert cookies_1["sRefreshToken"]["secure"] is None
    assert cookies_1["sIdRefreshToken"]["secure"] is None

    response_2 = driver_config_client.get(
        url="/handle",
        headers={"anti-csrf": response_1.headers.get("anti-csrf")},
        cookies={
            "sAccessToken": cookies_1["sAccessToken"]["value"],
            "sIdRefreshToken": cookies_1["sIdRefreshToken"]["value"],
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
            session.init(anti_csrf="VIA_TOKEN", cookie_domain="supertokens.io")
        ],
    )
    start_st()

    response_1 = driver_config_client.get("/login")
    cookies_1 = extract_all_cookies(response_1)

    assert response_1.headers.get("anti-csrf") is not None
    assert cookies_1["sAccessToken"]["domain"] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_1["sRefreshToken"]["domain"] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_1["sIdRefreshToken"]["domain"] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_1["sAccessToken"]["path"] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
    assert cookies_1["sRefreshToken"]["path"] == TEST_DRIVER_CONFIG_REFRESH_TOKEN_PATH
    assert cookies_1["sIdRefreshToken"]["path"] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
    assert cookies_1["sAccessToken"]["httponly"]
    assert cookies_1["sRefreshToken"]["httponly"]
    assert cookies_1["sIdRefreshToken"]["httponly"]
    assert (
        cookies_1["sAccessToken"]["samesite"].lower()
        == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    )
    assert (
        cookies_1["sRefreshToken"]["samesite"].lower()
        == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    )
    assert (
        cookies_1["sIdRefreshToken"]["samesite"].lower()
        == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    )
    assert cookies_1["sAccessToken"]["secure"] is None
    assert cookies_1["sRefreshToken"]["secure"] is None
    assert cookies_1["sIdRefreshToken"]["secure"] is None

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
            email: str, api_options: APIOptions, user_context: Dict[str, Any]
        ):
            response_dict = {"custom": True}
            api_options.response.set_status_code(203)
            api_options.response.set_json_content(response_dict)
            return await original_func(email, api_options, user_context)

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
        recipe_list=[session.init()],
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
        recipe_list=[session.init(), emailpassword.init()],
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
