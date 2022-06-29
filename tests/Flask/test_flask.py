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

from _pytest.fixtures import fixture
from flask import Flask, g, jsonify, make_response, request
from supertokens_python import InputAppInfo, SupertokensConfig, init
from supertokens_python.framework.flask import Middleware
from supertokens_python.recipe import emailpassword, session
from supertokens_python.recipe.emailpassword.interfaces import APIInterface, APIOptions
from supertokens_python.recipe.session import SessionContainer
from supertokens_python.recipe.session.framework.flask import verify_session
from supertokens_python.recipe.session.syncio import (
    create_new_session,
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
)


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
            email: str, api_options: APIOptions, user_context: Dict[str, Any]
        ):
            response_dict = {"custom": True}
            api_options.response.set_status_code(203)
            api_options.response.set_json_content(response_dict)
            return await original_func(email, api_options, user_context)

        original_implementation.email_exists_get = email_exists_get
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
            session.init(anti_csrf="VIA_TOKEN", cookie_domain="supertokens.io"),
            emailpassword.init(
                override=emailpassword.InputOverrideConfig(
                    apis=override_email_password_apis
                )
            ),
        ],
    )

    @app.route("/test")  # type: ignore
    def t():  # type: ignore
        return jsonify({})

    @app.route("/login")  # type: ignore
    def login():  # type: ignore
        user_id = "userId"
        create_new_session(request, user_id, {}, {})

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

    test_client = driver_config_app.test_client()
    test_client.set_cookie(
        "localhost", "sRefreshToken", cookies_1["sRefreshToken"]["value"]
    )
    test_client.set_cookie(
        "localhost", "sIdRefreshToken", cookies_1["sIdRefreshToken"]["value"]
    )
    response_2 = test_client.post(
        "/refresh", headers={"anti-csrf": response_1.headers.get("anti-csrf")}
    )
    cookies_2 = extract_all_cookies(response_2)
    assert cookies_1["sAccessToken"]["value"] != cookies_2["sAccessToken"]["value"]
    assert cookies_1["sRefreshToken"]["value"] != cookies_2["sRefreshToken"]["value"]
    assert (
        cookies_1["sIdRefreshToken"]["value"] != cookies_2["sIdRefreshToken"]["value"]
    )
    assert response_2.headers.get("anti-csrf") is not None
    assert cookies_2["sAccessToken"]["domain"] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_2["sRefreshToken"]["domain"] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_2["sIdRefreshToken"]["domain"] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_2["sAccessToken"]["path"] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
    assert cookies_2["sRefreshToken"]["path"] == TEST_DRIVER_CONFIG_REFRESH_TOKEN_PATH
    assert cookies_2["sIdRefreshToken"]["path"] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
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

    test_client = driver_config_app.test_client()
    test_client.set_cookie(
        "localhost", "sRefreshToken", cookies_1["sRefreshToken"]["value"]
    )
    test_client.set_cookie(
        "localhost", "sIdRefreshToken", cookies_1["sIdRefreshToken"]["value"]
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

    test_client = driver_config_app.test_client()
    test_client.set_cookie(
        "localhost", "sAccessToken", cookies_1["sAccessToken"]["value"]
    )
    test_client.set_cookie(
        "localhost", "sIdRefreshToken", cookies_1["sIdRefreshToken"]["value"]
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
    test_client.set_cookie(
        "localhost", "sIdRefreshToken", cookies_1["sIdRefreshToken"]["value"]
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
