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
from base64 import b64encode

import pytest
from _pytest.fixtures import fixture
from flask import Flask, g, jsonify, make_response, request
from supertokens_python import InputAppInfo, SupertokensConfig, init
from supertokens_python.framework.flask import Middleware
from supertokens_python.recipe import emailpassword, session, thirdparty
from supertokens_python.recipe.emailpassword.interfaces import APIInterface, APIOptions
from supertokens_python.recipe.session import SessionContainer
from supertokens_python.recipe.session.framework.flask import verify_session
from supertokens_python.recipe.session.syncio import (
    create_new_session,
    create_new_session_without_request_response,
    get_session,
    refresh_session,
    revoke_session,
)
from tests.Flask.utils import extract_all_cookies
from tests.utils import (
    TEST_ACCESS_TOKEN_MAX_AGE_CONFIG_KEY,
    TEST_ACCESS_TOKEN_MAX_AGE_VALUE,
    TEST_ACCESS_TOKEN_PATH_CONFIG_KEY,
    TEST_ACCESS_TOKEN_PATH_VALUE,
    TEST_COOKIE_DOMAIN_CONFIG_KEY,
    TEST_COOKIE_DOMAIN_VALUE,
    TEST_COOKIE_SAME_SITE_CONFIG_KEY,
    TEST_COOKIE_SECURE_CONFIG_KEY,
    TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH,
    TEST_DRIVER_CONFIG_COOKIE_DOMAIN,
    TEST_DRIVER_CONFIG_COOKIE_SAME_SITE,
    TEST_DRIVER_CONFIG_REFRESH_TOKEN_PATH,
    TEST_REFRESH_TOKEN_MAX_AGE_CONFIG_KEY,
    TEST_REFRESH_TOKEN_MAX_AGE_VALUE,
    TEST_REFRESH_TOKEN_PATH_CONFIG_KEY,
    TEST_REFRESH_TOKEN_PATH_KEY_VALUE,
    clean_st,
    reset,
    set_key_value_in_config,
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
from supertokens_python.recipe.dashboard.utils import DashboardConfig


def setup_function(_):
    reset()
    clean_st()
    setup_st()


def teardown_function(_):
    reset()
    clean_st()


@fixture(scope="function")
def driver_config_app():
    def override_email_password_apis(original_implementation: APIInterface):

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

    def override_dashboard_functions(original_implementation: RecipeInterface):
        async def should_allow_access(
            request: BaseRequest, __: DashboardConfig, ___: Dict[str, Any]
        ):
            auth_header = request.get_header("authorization")
            return auth_header == "Bearer testapikey"

        original_implementation.should_allow_access = should_allow_access  # type: ignore
        return original_implementation

    app = Flask(__name__)
    app.app_context().push()
    Middleware(app)

    app.testing = True
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
            emailpassword.init(
                override=emailpassword.InputOverrideConfig(
                    apis=override_email_password_apis
                )
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

    @app.route("/test")  # type: ignore
    def t():  # type: ignore
        return jsonify({})

    @app.route("/login")  # type: ignore
    def login():  # type: ignore
        user_id = "userId"
        create_new_session(request, "public", user_id, {}, {})

        return jsonify({"userId": user_id, "session": "ssss"})

    @app.route("/refresh", methods=["POST"])  # type: ignore
    def custom_refresh():  # type: ignore
        response = make_response(jsonify({}))
        refresh_session(request)
        return response

    @app.route("/info", methods=["GET", "OPTIONS"])  # type: ignore
    def custom_info():  # type: ignore
        if request.method == "OPTIONS":  # type: ignore
            return jsonify({"method": "option"})
        response = make_response(jsonify({}))
        get_session(request, True)
        return response

    @app.route("/handle", methods=["GET", "OPTIONS"])  # type: ignore
    def custom_handle_api():  # type: ignore
        if request.method == "OPTIONS":  # type: ignore
            return jsonify({"method": "option"})
        session: Union[None, SessionContainer] = get_session(request, True)
        if session is None:
            raise Exception("Should never come here")
        return jsonify({"s": session.get_user_id()})

    @app.route("/handle-session-optional", methods=["GET", "OPTIONS"])  # type: ignore
    @verify_session(session_required=False)
    def optional_session():  # type: ignore
        if request.method == "OPTIONS":  # type: ignore
            return jsonify({"method": "option"})
        session: Union[SessionContainer, None] = g.supertokens  # type: ignore
        if session is None:
            return jsonify({"s": "empty session"})
        return jsonify({"s": session.get_user_id()})

    @app.route("/logout", methods=["POST"])  # type: ignore
    @verify_session(session_required=False)
    def custom_logout():  # type: ignore
        response = make_response(jsonify({}))
        session: Union[None, SessionContainer] = get_session(request, True)
        if session is None:
            raise Exception("Should never come here")
        revoke_session(session.get_user_id())
        return response

    return app


def test_cookie_login_and_refresh(driver_config_app: Any):
    start_st()

    set_key_value_in_config(TEST_COOKIE_SAME_SITE_CONFIG_KEY, "None")
    set_key_value_in_config(
        TEST_ACCESS_TOKEN_MAX_AGE_CONFIG_KEY, TEST_ACCESS_TOKEN_MAX_AGE_VALUE
    )
    set_key_value_in_config(
        TEST_ACCESS_TOKEN_PATH_CONFIG_KEY, TEST_ACCESS_TOKEN_PATH_VALUE
    )
    set_key_value_in_config(TEST_COOKIE_DOMAIN_CONFIG_KEY, TEST_COOKIE_DOMAIN_VALUE)
    set_key_value_in_config(
        TEST_REFRESH_TOKEN_MAX_AGE_CONFIG_KEY, TEST_REFRESH_TOKEN_MAX_AGE_VALUE
    )
    set_key_value_in_config(
        TEST_REFRESH_TOKEN_PATH_CONFIG_KEY, TEST_REFRESH_TOKEN_PATH_KEY_VALUE
    )
    set_key_value_in_config(TEST_COOKIE_SECURE_CONFIG_KEY, "false")

    response_1 = driver_config_app.test_client().get("/login")
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

    test_client = driver_config_app.test_client()
    test_client.set_cookie(
        "localhost", "sRefreshToken", cookies_1["sRefreshToken"]["value"]
    )
    response_2 = test_client.post(
        "/refresh", headers={"anti-csrf": response_1.headers.get("anti-csrf")}
    )
    cookies_2 = extract_all_cookies(response_2)
    assert cookies_1["sAccessToken"]["value"] != cookies_2["sAccessToken"]["value"]
    assert cookies_1["sRefreshToken"]["value"] != cookies_2["sRefreshToken"]["value"]
    assert response_2.headers.get("anti-csrf") is not None
    assert cookies_2["sAccessToken"]["domain"] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_2["sRefreshToken"]["domain"] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_2["sAccessToken"]["path"] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
    assert cookies_2["sRefreshToken"]["path"] == TEST_DRIVER_CONFIG_REFRESH_TOKEN_PATH
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


def test_login_refresh_no_csrf(driver_config_app: Any):
    start_st()

    set_key_value_in_config(TEST_COOKIE_SAME_SITE_CONFIG_KEY, "None")
    set_key_value_in_config(
        TEST_ACCESS_TOKEN_MAX_AGE_CONFIG_KEY, TEST_ACCESS_TOKEN_MAX_AGE_VALUE
    )
    set_key_value_in_config(
        TEST_ACCESS_TOKEN_PATH_CONFIG_KEY, TEST_ACCESS_TOKEN_PATH_VALUE
    )
    set_key_value_in_config(TEST_COOKIE_DOMAIN_CONFIG_KEY, TEST_COOKIE_DOMAIN_VALUE)
    set_key_value_in_config(
        TEST_REFRESH_TOKEN_MAX_AGE_CONFIG_KEY, TEST_REFRESH_TOKEN_MAX_AGE_VALUE
    )
    set_key_value_in_config(
        TEST_REFRESH_TOKEN_PATH_CONFIG_KEY, TEST_REFRESH_TOKEN_PATH_KEY_VALUE
    )
    set_key_value_in_config(TEST_COOKIE_SECURE_CONFIG_KEY, "false")

    response_1 = driver_config_app.test_client().get("/login")
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

    test_client = driver_config_app.test_client()
    test_client.set_cookie(
        "localhost", "sRefreshToken", cookies_1["sRefreshToken"]["value"]
    )

    # post with csrf token -> no error
    result = test_client.post(
        "/refresh", headers={"anti-csrf": response_1.headers.get("anti-csrf")}
    )
    assert result.status_code == 200

    # post with csrf token -> should be error with status code 401
    result = test_client.post("/refresh")
    assert result.status_code == 401


def test_login_logout(driver_config_app: Any):
    start_st()

    set_key_value_in_config(TEST_COOKIE_SAME_SITE_CONFIG_KEY, "None")
    set_key_value_in_config(
        TEST_ACCESS_TOKEN_MAX_AGE_CONFIG_KEY, TEST_ACCESS_TOKEN_MAX_AGE_VALUE
    )
    set_key_value_in_config(
        TEST_ACCESS_TOKEN_PATH_CONFIG_KEY, TEST_ACCESS_TOKEN_PATH_VALUE
    )
    set_key_value_in_config(TEST_COOKIE_DOMAIN_CONFIG_KEY, TEST_COOKIE_DOMAIN_VALUE)
    set_key_value_in_config(
        TEST_REFRESH_TOKEN_MAX_AGE_CONFIG_KEY, TEST_REFRESH_TOKEN_MAX_AGE_VALUE
    )
    set_key_value_in_config(
        TEST_REFRESH_TOKEN_PATH_CONFIG_KEY, TEST_REFRESH_TOKEN_PATH_KEY_VALUE
    )
    set_key_value_in_config(TEST_COOKIE_SECURE_CONFIG_KEY, "false")

    response_1 = driver_config_app.test_client().get("/login")
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

    test_client = driver_config_app.test_client()
    test_client.set_cookie(
        "localhost", "sAccessToken", cookies_1["sAccessToken"]["value"]
    )

    response_2 = test_client.post(
        "/logout", headers={"anti-csrf": response_1.headers.get("anti-csrf")}
    )

    cookies_2 = extract_all_cookies(response_2)
    assert not cookies_2

    response_3 = test_client.post(
        "/logout", headers={"anti-csrf": response_1.headers.get("anti-csrf")}
    )

    assert response_3.status_code == 200


def test_login_handle(driver_config_app: Any):
    start_st()

    set_key_value_in_config(TEST_COOKIE_SAME_SITE_CONFIG_KEY, "None")
    set_key_value_in_config(
        TEST_ACCESS_TOKEN_MAX_AGE_CONFIG_KEY, TEST_ACCESS_TOKEN_MAX_AGE_VALUE
    )
    set_key_value_in_config(
        TEST_ACCESS_TOKEN_PATH_CONFIG_KEY, TEST_ACCESS_TOKEN_PATH_VALUE
    )
    set_key_value_in_config(TEST_COOKIE_DOMAIN_CONFIG_KEY, TEST_COOKIE_DOMAIN_VALUE)
    set_key_value_in_config(
        TEST_REFRESH_TOKEN_MAX_AGE_CONFIG_KEY, TEST_REFRESH_TOKEN_MAX_AGE_VALUE
    )
    set_key_value_in_config(
        TEST_REFRESH_TOKEN_PATH_CONFIG_KEY, TEST_REFRESH_TOKEN_PATH_KEY_VALUE
    )
    set_key_value_in_config(TEST_COOKIE_SECURE_CONFIG_KEY, "false")

    response_1 = driver_config_app.test_client().get("/login")
    cookies_1 = extract_all_cookies(response_1)
    test_client = driver_config_app.test_client()
    test_client.set_cookie(
        "localhost", "sAccessToken", cookies_1["sAccessToken"]["value"]
    )

    response_2 = test_client.get(
        "/handle", headers={"anti-csrf": response_1.headers.get("anti-csrf")}
    )

    response_dict = json.loads(response_2.data)
    assert "s" in response_dict


def test_custom_response(driver_config_app: Any):
    start_st()

    test_client = driver_config_app.test_client()
    response = test_client.get("/auth/signup/email/exists?email=test@example.com")

    dict_response = json.loads(response.data)
    assert response.status_code == 203
    assert dict_response["custom"]


def test_optional_session(driver_config_app: Any):
    start_st()

    test_client = driver_config_app.test_client()
    response = test_client.get("/handle-session-optional")

    dict_response = json.loads(response.data)
    assert response.status_code == 200
    assert dict_response["s"] == "empty session"


def test_thirdparty_parsing_works(driver_config_app: Any):
    start_st()

    test_client = driver_config_app.test_client()
    state = b64encode(
        json.dumps({"frontendRedirectURI": "http://localhost:3000/redirect"}).encode()
    ).decode()
    code = "testing"

    data = {"state": state, "code": code}
    res = test_client.post("/auth/callback/apple", data=data)

    assert res.status_code == 303
    assert res.data == b""
    assert (
        res.headers["location"]
        == f"http://localhost:3000/redirect?state={state.replace('=', '%3D')}&code={code}"
    )


from flask.wrappers import Response
from supertokens_python.framework.flask.flask_response import (
    FlaskResponse as SupertokensFlaskWrapper,
)


def test_remove_header_works():
    response = Response()
    st_response = SupertokensFlaskWrapper(response)

    st_response.set_header("foo", "bar")
    assert st_response.get_header("foo") == "bar"
    st_response.remove_header("foo")
    assert st_response.get_header("foo") is None


@pytest.mark.asyncio
async def test_dashboard_search_tags(driver_config_app: Any):
    start_st()
    querier = Querier.get_instance(DashboardRecipe.recipe_id)
    cdiVersion = await querier.get_api_version()
    if not cdiVersion:
        pytest.skip()
    if not is_version_gte(cdiVersion, "2.20"):
        pytest.skip()
    test_client = driver_config_app.test_client()
    response = test_client.get(
        "/auth/dashboard/api/search/tags",
        headers={
            "Authorization": "Bearer testapikey",
            "Content-Type": "application/json",
        },
    )

    assert response.status_code == 200
    data_json = json.loads(response.data)
    assert len(data_json["tags"]) != 0


@pytest.mark.asyncio
async def test_search_with_email_t(driver_config_app: Any):
    start_st()
    querier = Querier.get_instance(DashboardRecipe.recipe_id)
    cdi_version = await querier.get_api_version()
    if not cdi_version:
        pytest.skip()
    if not is_version_gte(cdi_version, "2.20"):
        pytest.skip()
    await create_users(emailpassword=True)
    test_client = driver_config_app.test_client()
    query = {"limit": "10", "email": "t"}
    response = test_client.get(
        "/auth/dashboard/api/users",
        headers={
            "Authorization": "Bearer testapikey",
            "Content-Type": "application/json",
        },
        query_string=query,
    )

    assert response.status_code == 200
    data_json = json.loads(response.data)
    assert len(data_json["users"]) == 5


@pytest.mark.asyncio
async def test_search_with_multiple_email_search_terms(driver_config_app: Any):
    start_st()
    querier = Querier.get_instance(DashboardRecipe.recipe_id)
    cdi_version = await querier.get_api_version()
    if not cdi_version:
        pytest.skip()
    if not is_version_gte(cdi_version, "2.20"):
        pytest.skip()
    await create_users(emailpassword=True)
    test_client = driver_config_app.test_client()
    query = {"limit": "10", "email": "iresh;john"}
    response = test_client.get(
        "/auth/dashboard/api/users",
        headers={
            "Authorization": "Bearer testapikey",
            "Content-Type": "application/json",
        },
        query_string=query,
    )

    assert response.status_code == 200
    data_json = json.loads(response.data)
    assert len(data_json["users"]) == 1


@pytest.mark.asyncio
async def test_search_with_email_iresh(driver_config_app: Any):
    start_st()
    querier = Querier.get_instance(DashboardRecipe.recipe_id)
    cdi_version = await querier.get_api_version()
    if not cdi_version:
        pytest.skip()
    if not is_version_gte(cdi_version, "2.20"):
        pytest.skip()
    await create_users(emailpassword=True)
    test_client = driver_config_app.test_client()
    query = {"limit": "10", "email": "iresh"}
    response = test_client.get(
        "/auth/dashboard/api/users",
        headers={
            "Authorization": "Bearer testapikey",
            "Content-Type": "application/json",
        },
        query_string=query,
    )

    assert response.status_code == 200
    data_json = json.loads(response.data)
    assert len(data_json["users"]) == 0


@pytest.mark.asyncio
async def test_search_with_phone_plus_one(driver_config_app: Any):
    start_st()
    querier = Querier.get_instance(DashboardRecipe.recipe_id)
    cdi_version = await querier.get_api_version()
    if not cdi_version:
        pytest.skip()
    if not is_version_gte(cdi_version, "2.20"):
        pytest.skip()
    await create_users(passwordless=True)
    test_client = driver_config_app.test_client()
    query = {"limit": "10", "phone": "+1"}
    response = test_client.get(
        "/auth/dashboard/api/users",
        headers={
            "Authorization": "Bearer testapikey",
            "Content-Type": "application/json",
        },
        query_string=query,
    )

    assert response.status_code == 200
    data_json = json.loads(response.data)
    assert len(data_json["users"]) == 3


@pytest.mark.asyncio
async def test_search_with_phone_one_bracket(driver_config_app: Any):
    start_st()
    querier = Querier.get_instance(DashboardRecipe.recipe_id)
    cdi_version = await querier.get_api_version()
    if not cdi_version:
        pytest.skip()
    if not is_version_gte(cdi_version, "2.20"):
        pytest.skip()
    await create_users(passwordless=True)
    test_client = driver_config_app.test_client()
    query = {"limit": "10", "phone": "1("}
    response = test_client.get(
        "/auth/dashboard/api/users",
        headers={
            "Authorization": "Bearer testapikey",
            "Content-Type": "application/json",
        },
        query_string=query,
    )

    assert response.status_code == 200
    data_json = json.loads(response.data)
    assert len(data_json["users"]) == 0


@pytest.mark.asyncio
async def test_search_with_provider_google(driver_config_app: Any):
    start_st()
    querier = Querier.get_instance(DashboardRecipe.recipe_id)
    cdi_version = await querier.get_api_version()
    if not cdi_version:
        pytest.skip()
    if not is_version_gte(cdi_version, "2.20"):
        pytest.skip()
    await create_users(emailpassword=False, passwordless=False, thirdparty=True)
    test_client = driver_config_app.test_client()
    query = {"limit": "10", "provider": "google"}
    response = test_client.get(
        "/auth/dashboard/api/users",
        headers={
            "Authorization": "Bearer testapikey",
            "Content-Type": "application/json",
        },
        query_string=query,
    )

    assert response.status_code == 200
    data_json = json.loads(response.data)
    assert len(data_json["users"]) == 3


@pytest.mark.asyncio
async def test_search_with_provider_google_and_phone_one(driver_config_app: Any):
    start_st()
    querier = Querier.get_instance(DashboardRecipe.recipe_id)
    cdi_version = await querier.get_api_version()
    if not cdi_version:
        pytest.skip()
    if not is_version_gte(cdi_version, "2.20"):
        pytest.skip()
    await create_users(emailpassword=False, passwordless=True, thirdparty=True)
    test_client = driver_config_app.test_client()
    query = {"limit": "10", "provider": "google", "phone": "1"}
    response = test_client.get(
        "/auth/dashboard/api/users",
        headers={
            "Authorization": "Bearer testapikey",
            "Content-Type": "application/json",
        },
        query_string=query,
    )

    assert response.status_code == 200
    data_json = json.loads(response.data)
    assert len(data_json["users"]) == 0


from tests.utils import get_st_init_args


@fixture(scope="function")
def flask_app():
    app = Flask(__name__)
    Middleware(app)

    app.testing = True

    counter: Dict[str, int] = {}

    @app.before_request  # type: ignore
    @verify_session(session_required=False)
    def audit_request():  # type: ignore
        nonlocal counter

        user_id = None
        s: SessionContainer = g.supertokens

        if s:
            user_id = s.get_user_id()
            print(f"User {user_id} tried to accesss {request.path}")
        else:
            user_id = "unknown"
            print(f"Unknown user tried to access {request.path}")

        if request.path != "/stats":
            counter[user_id] = counter.get(user_id, 0) + 1

    @app.route("/stats")  # type: ignore
    def test_api():  # type: ignore
        return jsonify(counter)

    @app.route("/login")  # type: ignore
    def login():  # type: ignore
        user_id = "userId"
        s = create_new_session(request, "public", user_id, {}, {})
        return jsonify({"user": s.get_user_id()})

    @app.route("/ping")  # type: ignore
    def ping():  # type: ignore
        return jsonify({"msg": "pong"})

    @app.route("/options-api", methods=["OPTIONS", "GET"])  # type: ignore
    @verify_session()
    def options_api():  # type: ignore
        return jsonify({"msg": "Shouldn't come here"})

    @app.get("/verify")  # type: ignore
    @verify_session()
    def verify_api():  # type: ignore
        return {"handle": g.supertokens.get_handle()}

    return app


def test_verify_session_with_before_request_with_no_response(flask_app: Any):
    init(**{**get_st_init_args([session.init(get_token_transfer_method=lambda *_: "cookie")]), "framework": "flask"})  # type: ignore
    start_st()

    client = flask_app.test_client()

    assert client.get("stats").json == {}

    assert client.get("/ping").status_code == 200

    assert client.get("stats").json == {"unknown": 1}

    with pytest.raises(Exception) as e:
        client.options("/options-api")

    assert str(e.value) == "verify_session cannot be used with options method"

    assert client.get("stats").json == {"unknown": 2}

    assert client.get("/login").status_code == 200

    assert client.get("/stats").json == {"unknown": 3}

    assert client.get("/ping").status_code == 200

    assert client.get("/stats").json == {"unknown": 3, "userId": 1}

    assert client.get("/ping").status_code == 200

    assert client.get("/stats").json == {"unknown": 3, "userId": 2}


@fixture(scope="function")
def flask_app_without_middleware():
    app = Flask(__name__)

    app.testing = True

    @app.get("/verify")  # type: ignore
    @verify_session()
    def verify_api():  # type: ignore
        return {"handle": g.supertokens.get_handle()}

    return app


def test_that_verify_session_return_401_if_access_token_is_not_sent_and_middleware_is_not_added(
    flask_app: Any, flask_app_without_middleware: Any
):
    init(**{**get_st_init_args([session.init(get_token_transfer_method=lambda *_: "header")]), "framework": "flask"})  # type: ignore
    start_st()

    client = flask_app.test_client()
    client_without_middleware = flask_app_without_middleware.test_client()

    res = client.get("/verify")
    assert res.status_code == 401
    assert res.json == {"message": "unauthorised"}

    s = create_new_session_without_request_response("public", "userId", {}, {})
    res = client.get(
        "/verify", headers={"Authorization": "Bearer " + s.get_access_token()}
    )
    assert res.status_code == 200
    assert list(res.json) == ["handle"]

    # Client without middleware
    res = client_without_middleware.get("/verify")
    assert res.status_code == 401
    assert res.json == {"message": "unauthorised"}

    res = client_without_middleware.get(
        "/verify", headers={"Authorization": "Bearer " + s.get_access_token()}
    )
    assert res.status_code == 200
