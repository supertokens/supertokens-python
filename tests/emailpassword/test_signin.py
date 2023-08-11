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
from typing import Union

from fastapi import FastAPI
from fastapi.requests import Request
from fastapi.testclient import TestClient
from pytest import fixture, mark
from supertokens_python import InputAppInfo, SupertokensConfig, init
from supertokens_python.asyncio import delete_user, get_user_count
from supertokens_python.framework.fastapi import get_middleware
from supertokens_python.querier import Querier
from supertokens_python.recipe import emailpassword, session
from supertokens_python.recipe.emailpassword.interfaces import APIInterface
from supertokens_python.recipe.session import SessionContainer
from supertokens_python.recipe.session.asyncio import (
    create_new_session,
    get_session,
    refresh_session,
)
from supertokens_python.utils import is_version_gte
from tests.utils import (
    clean_st,
    extract_all_cookies,
    reset,
    setup_st,
    sign_up_request,
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

    @app.post("/logout")
    async def custom_logout(request: Request):  # type: ignore
        session: Union[None, SessionContainer] = await get_session(request, True)
        if session is None:
            raise Exception("Should never come here")
        await session.revoke_session()
        return {}  # type: ignore

    return TestClient(app)


@mark.asyncio
async def test_that_disabling_api_the_default_signin_API_does_not_work(
    driver_config_client: TestClient,
):
    def apis_override_email_password(param: APIInterface):
        param.disable_sign_in_post = True
        return param

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
                    apis=apis_override_email_password
                )
            )
        ],
    )
    start_st()

    response_1 = driver_config_client.post(
        url="/auth/signin",
        json={
            "formFields": [
                {"id": "password", "value": "validpass123"},
                {"id": "email", "value": "random@gmail.com"},
            ]
        },
    )

    assert response_1.status_code == 404


@mark.asyncio
async def test_singinAPI_works_when_input_is_fine(driver_config_client: TestClient):
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
            emailpassword.init(),
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
        ],
    )
    start_st()

    response_1 = sign_up_request(
        driver_config_client, "random@gmail.com", "validpass123"
    )
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    user_info = dict_response["user"]
    assert dict_response["status"] == "OK"

    response_2 = driver_config_client.post(
        url="/auth/signin",
        json={
            "formFields": [
                {"id": "password", "value": "validpass123"},
                {"id": "email", "value": "random@gmail.com"},
            ]
        },
    )

    assert response_2.status_code == 200
    dict_response = json.loads(response_2.text)
    assert dict_response["user"]["id"] == user_info["id"]
    assert dict_response["user"]["email"] == user_info["email"]


@mark.asyncio
async def test_singinAPI_throws_an_error_when_email_does_not_match(
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
        framework="fastapi",
        recipe_list=[
            emailpassword.init(),
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
        ],
    )
    start_st()

    response_1 = sign_up_request(
        driver_config_client, "random@gmail.com", "validpass123"
    )
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"

    response_2 = driver_config_client.post(
        url="/auth/signin",
        json={
            "formFields": [
                {"id": "password", "value": "validpass123"},
                {"id": "email", "value": "ra@gmail.com"},
            ]
        },
    )

    assert response_2.status_code == 200
    dict_response = json.loads(response_2.text)
    assert dict_response["status"] == "WRONG_CREDENTIALS_ERROR"


@mark.asyncio
async def test_singin_api_throws_an_error_when_email_does_not_match(
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
        framework="fastapi",
        recipe_list=[
            emailpassword.init(),
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
        ],
    )
    start_st()

    response_1 = sign_up_request(
        driver_config_client, "random@gmail.com", "validpass123"
    )
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"

    response_2 = driver_config_client.post(
        url="/auth/signin",
        json={
            "formFields": [
                {"id": "password", "value": "validpass123"},
                {"id": "email", "value": "ra@gmail.com"},
            ]
        },
    )

    assert response_2.status_code == 200
    dict_response = json.loads(response_2.text)
    assert dict_response["status"] == "WRONG_CREDENTIALS_ERROR"


@mark.asyncio
async def test_singinAPI_throws_an_error_if_password_is_incorrect(
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
        framework="fastapi",
        recipe_list=[
            emailpassword.init(),
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
        ],
    )
    start_st()

    response_1 = sign_up_request(
        driver_config_client, "random@gmail.com", "validpass123"
    )
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"

    response_2 = driver_config_client.post(
        url="/auth/signin",
        json={
            "formFields": [
                {"id": "password", "value": "wrong_password"},
                {"id": "email", "value": "random@gmail.com"},
            ]
        },
    )

    assert response_2.status_code == 200
    dict_response = json.loads(response_2.text)
    assert dict_response["status"] == "WRONG_CREDENTIALS_ERROR"


@mark.asyncio
async def test_bad_input_not_a_JSON_to_signin_api(driver_config_client: TestClient):
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
            emailpassword.init(),
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
        ],
    )
    start_st()

    response_1 = sign_up_request(
        driver_config_client, "random@gmail.com", "validpass123"
    )
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"

    response_2 = driver_config_client.post(url="/auth/signin", json={"x": "y"})

    assert response_2.status_code == 400
    dict_response = json.loads(response_2.text)
    assert dict_response["message"] == "Are you sending too many / too few formFields?"


@mark.asyncio
async def test_bad_input_not_a_JSON_to_signin_API(driver_config_client: TestClient):
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
            emailpassword.init(),
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
        ],
    )
    start_st()

    response_1 = sign_up_request(
        driver_config_client, "random@gmail.com", "validpass123"
    )
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"

    response_2 = driver_config_client.post(url="/auth/signin", json={"x": "y"})

    assert response_2.status_code == 400
    dict_response = json.loads(response_2.text)
    assert dict_response["message"] == "Are you sending too many / too few formFields?"


@mark.asyncio
async def test_that_a_successful_signin_yields_a_session(
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
        framework="fastapi",
        recipe_list=[
            emailpassword.init(),
            session.init(
                anti_csrf="VIA_TOKEN",
                get_token_transfer_method=lambda _, __, ___: "cookie",
            ),
        ],
    )
    start_st()

    response_1 = sign_up_request(
        driver_config_client, "random@gmail.com", "validpass123"
    )
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"

    response_2 = driver_config_client.post(
        url="/auth/signin",
        json={
            "formFields": [
                {"id": "password", "value": "validpass123"},
                {"id": "email", "value": "random@gmail.com"},
            ]
        },
    )

    assert response_2.status_code == 200

    cookies = extract_all_cookies(response_1)

    assert cookies["sAccessToken"] is not None
    assert cookies["sRefreshToken"] is not None
    assert response_2.headers.get("anti-csrf") is not None


@mark.asyncio
async def test_email_field_validation_error(driver_config_client: TestClient):
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
            emailpassword.init(),
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
        ],
    )
    start_st()

    response_1 = sign_up_request(
        driver_config_client, "random@gmail.com", "validpassword123"
    )
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"

    response_2 = driver_config_client.post(
        url="/auth/signin",
        json={
            "formFields": [
                {"id": "password", "value": "validpassword123"},
                {"id": "email", "value": "randomgmail.com"},
            ]
        },
    )

    assert response_2.status_code == 200
    dict_response = json.loads(response_2.text)
    assert dict_response["status"] == "FIELD_ERROR"


@mark.asyncio
async def test_formFields_has_no_email_field(driver_config_client: TestClient):
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
            emailpassword.init(),
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
        ],
    )
    start_st()

    response_1 = sign_up_request(
        driver_config_client, "random@gmail.com", "validpassword123"
    )
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"

    response_2 = driver_config_client.post(
        url="/auth/signin",
        json={"formFields": [{"id": "password", "value": "validpassword123"}]},
    )

    assert response_2.status_code == 400


@mark.asyncio
async def test_formFields_has_no_password_field(driver_config_client: TestClient):
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
            emailpassword.init(),
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
        ],
    )
    start_st()

    response_1 = sign_up_request(
        driver_config_client, "random@gmail.com", "validpassword123"
    )
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"

    response_2 = driver_config_client.post(
        url="/auth/signin",
        json={"formFields": [{"id": "email", "value": "randomgmail.com"}]},
    )

    assert response_2.status_code == 400


@mark.asyncio
async def test_delete_user(driver_config_client: TestClient):
    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth",
        ),
        framework="fastapi",
        recipe_list=[emailpassword.init(), session.init(anti_csrf="VIA_TOKEN")],
    )
    start_st()

    response_1 = sign_up_request(
        driver_config_client, "random@gmail.com", "validpass123"
    )
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"

    user_count = await get_user_count()
    assert user_count == 1

    version = await Querier.get_instance().get_api_version()

    if is_version_gte(version, "2.10"):
        await delete_user(dict_response["user"]["id"])
        user_count = await get_user_count()
        assert user_count == 0
    else:
        error_raised = True
        try:
            await delete_user(dict_response["user"]["id"])
            error_raised = False
        except Exception:
            pass

        assert error_raised


# TODO add few more tests
