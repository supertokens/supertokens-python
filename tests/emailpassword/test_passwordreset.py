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
import asyncio
import json
from typing import Any, Dict, Union

from fastapi import FastAPI
from fastapi.requests import Request
from fastapi.testclient import TestClient
from pytest import fixture, mark
from supertokens_python import InputAppInfo, SupertokensConfig, init
from supertokens_python.framework.fastapi import get_middleware
from supertokens_python.recipe import emailpassword, session
from supertokens_python.recipe.emailpassword.types import User
from supertokens_python.recipe.session import SessionContainer
from supertokens_python.recipe.session.asyncio import (
    create_new_session,
    get_session,
    refresh_session,
)
from tests.utils import clean_st, reset, setup_st, sign_up_request, start_st


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

    @app.post("/logout")
    async def custom_logout(request: Request):  # type: ignore
        session: Union[None, SessionContainer] = await get_session(request, True)
        if session is None:
            raise Exception("Should never come here")
        await session.revoke_session()
        return {}  # type: ignore

    return TestClient(app)


@mark.asyncio
async def test_email_validation_checks_in_generate_token_API(
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
        recipe_list=[emailpassword.init()],
    )
    start_st()

    for invalid_email in ["random", 5]:
        res = driver_config_client.post(
            url="/auth/user/password/reset/token",
            json={"formFields": [{"id": "email", "value": invalid_email}]},
        )

        assert res.status_code == 200
        dict_res = json.loads(res.text)
        assert dict_res["status"] == "FIELD_ERROR"


@mark.asyncio
async def test_that_generated_password_link_is_correct(
    driver_config_client: TestClient,
):
    reset_url = None
    token_info: Union[None, str] = None
    rid_info: Union[None, str] = None

    async def custom_f(_: User, password_reset_url_with_token: str, __: Dict[str, Any]):
        nonlocal reset_url, token_info, rid_info
        reset_url = password_reset_url_with_token.split("?")[0]
        token_info = password_reset_url_with_token.split("?")[1].split("&")[0]
        rid_info = password_reset_url_with_token.split("?")[1].split("&")[1]

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
            session.init(),
            emailpassword.init(
                reset_password_using_token_feature=emailpassword.InputResetPasswordUsingTokenFeature(
                    create_and_send_custom_email=custom_f
                )
            ),
        ],
    )
    start_st()

    response_1 = sign_up_request(driver_config_client, "test@gmail.com", "testPass123")
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"
    await asyncio.sleep(1)
    response_1 = driver_config_client.post(
        url="/auth/user/password/reset/token",
        json={"formFields": [{"id": "email", "value": "test@gmail.com"}]},
    )
    await asyncio.sleep(1)

    assert response_1.status_code == 200
    assert reset_url == "http://supertokens.io/auth/reset-password"
    assert token_info is not None and "token=" in token_info  # type: ignore pylint: disable=unsupported-membership-test
    assert rid_info is not None and "rid=emailpassword" in rid_info  # type: ignore pylint: disable=unsupported-membership-test


@mark.asyncio
async def test_password_validation(driver_config_client: TestClient):
    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth",
        ),
        framework="fastapi",
        recipe_list=[emailpassword.init()],
    )
    start_st()

    response_1 = driver_config_client.post(
        url="/auth/user/password/reset",
        json={
            "formFields": [{"id": "password", "value": "invalid"}],
            "token": "random",
        },
    )

    assert response_1.status_code == 200
    # dict_response = json.loads(response_1.text)
    # assert dict_response["status"] == "FIELD_ERROR"

    response_2 = driver_config_client.post(
        url="/auth/user/password/reset",
        json={
            "formFields": [{"id": "password", "value": "validpass123"}],
            "token": "randomToken",
        },
    )

    assert response_2.status_code == 200
    dict_response = json.loads(response_2.text)
    assert dict_response["status"] != "FIELD_ERROR"


@mark.asyncio
async def test_token_missing_from_input(driver_config_client: TestClient):
    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth",
        ),
        framework="fastapi",
        recipe_list=[emailpassword.init()],
    )
    start_st()

    response_1 = driver_config_client.post(
        url="/auth/user/password/reset",
        json={"formFields": [{"id": "password", "value": "validpass123"}]},
    )

    assert response_1.status_code == 400
    dict_response = json.loads(response_1.text)
    assert dict_response["message"] == "Please provide the password reset token"


@mark.asyncio
async def test_valid_token_input_and_passoword_has_changed(
    driver_config_client: TestClient,
):
    token_info = None

    async def custom_f(_: User, password_reset_url_with_token: str, __: Dict[str, Any]):
        nonlocal token_info
        token_info = (
            password_reset_url_with_token.split("?")[1].split("&")[0].split("=")[1]
        )

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
                reset_password_using_token_feature=emailpassword.InputResetPasswordUsingTokenFeature(
                    create_and_send_custom_email=custom_f
                )
            ),
            session.init(),
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
    response_1 = driver_config_client.post(
        url="/auth/user/password/reset/token",
        json={"formFields": [{"id": "email", "value": "random@gmail.com"}]},
    )
    await asyncio.sleep(1)

    assert response_1.status_code == 200

    response_2 = driver_config_client.post(
        url="/auth/user/password/reset",
        json={
            "formFields": [{"id": "password", "value": "validpass12345"}],
            "token": token_info,
        },
    )
    await asyncio.sleep(1)
    assert response_2.status_code == 200

    response_3 = driver_config_client.post(
        url="/auth/signin",
        json={
            "formFields": [
                {"id": "password", "value": "validpass123"},
                {"id": "email", "value": "random@gmail.com"},
            ]
        },
    )

    assert response_3.status_code == 200

    dict_response = json.loads(response_3.text)
    assert dict_response["status"] == "WRONG_CREDENTIALS_ERROR"

    response_4 = driver_config_client.post(
        url="/auth/signin",
        json={
            "formFields": [
                {
                    "id": "password",
                    "value": "validpass12345",
                },
                {
                    "id": "email",
                    "value": "random@gmail.com",
                },
            ]
        },
    )

    assert response_4.status_code == 200

    dict_response = json.loads(response_4.text)
    assert dict_response["status"] == "OK"
    assert dict_response["user"]["id"] == user_info["id"]
    assert dict_response["user"]["email"] == user_info["email"]
