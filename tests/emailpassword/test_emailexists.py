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
from supertokens_python.framework.fastapi import get_middleware
from supertokens_python.recipe import emailpassword, session
from supertokens_python.recipe.emailpassword.interfaces import APIInterface
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


def apis_override_email_password(param: APIInterface):
    param.disable_email_exists_get = True
    return param


@mark.asyncio
async def test_good_input_email_exists(driver_config_client: TestClient):
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
            session.init(anti_csrf="VIA_TOKEN", cookie_domain="supertokens.io"),
            emailpassword.init(),
        ],
    )
    start_st()

    response_1 = sign_up_request(
        driver_config_client, "random@gmail.com", "validPass123"
    )

    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"

    response_2 = driver_config_client.get(
        url="/auth/signup/email/exists", params={"email": "random@gmail.com"}
    )
    assert response_2.status_code == 200


@mark.asyncio
async def test_good_input_email_does_not_exists(driver_config_client: TestClient):
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
            session.init(anti_csrf="VIA_TOKEN", cookie_domain="supertokens.io"),
            emailpassword.init(),
        ],
    )
    start_st()

    response_1 = driver_config_client.get(
        url="/auth/signup/email/exists", params={"email": "random@gmail.com"}
    )

    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"
    assert dict_response["exists"] is False


@mark.asyncio
async def test_that_if_disabling_api_the_default_email_exists_api_does_not_work(
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
            session.init(anti_csrf="VIA_TOKEN", cookie_domain="supertokens.io"),
            emailpassword.init(
                override=emailpassword.InputOverrideConfig(
                    apis=apis_override_email_password
                )
            ),
        ],
    )
    start_st()

    response_1 = driver_config_client.get(
        url="/auth/signup/email/exists", params={"email": "random@gmail.com"}
    )

    assert response_1.status_code == 404


@mark.asyncio
async def test_email_exists_a_syntactically_invalid_email(
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
            session.init(anti_csrf="VIA_TOKEN", cookie_domain="supertokens.io"),
            emailpassword.init(),
        ],
    )
    start_st()

    response_1 = sign_up_request(
        driver_config_client, "random@gmail.com", "validPass123"
    )

    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"

    response_2 = driver_config_client.get(
        url="/auth/signup/email/exists", params={"email": "randomgmail.com"}
    )
    assert response_2.status_code == 200
    dict_response = json.loads(response_2.text)
    assert dict_response["status"] == "OK"
    assert dict_response["exists"] is False


@mark.asyncio
async def test_sending_an_unnormalised_email_and_you_get_exists_is_true(
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
            session.init(anti_csrf="VIA_TOKEN", cookie_domain="supertokens.io"),
            emailpassword.init(),
        ],
    )
    start_st()

    response_1 = sign_up_request(
        driver_config_client, "random@gmail.com", "validPass123"
    )

    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"

    response_2 = driver_config_client.get(
        url="/auth/signup/email/exists", params={"email": "rAndOM@gmAiL.COm"}
    )
    assert response_2.status_code == 200
    dict_response = json.loads(response_2.text)
    assert dict_response["status"] == "OK"
    assert dict_response["exists"] is True


@mark.asyncio
async def test_bad_input_do_not_pass_email(driver_config_client: TestClient):
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
            session.init(anti_csrf="VIA_TOKEN", cookie_domain="supertokens.io"),
            emailpassword.init(),
        ],
    )
    start_st()

    response_1 = sign_up_request(
        driver_config_client, "random@gmail.com", "validPass123"
    )

    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"

    response_2 = driver_config_client.get(url="/auth/signup/email/exists", params={})
    assert response_2.status_code == 400
    assert "Please provide the email as a GET param" in response_2.text


@mark.asyncio
async def test_passing_an_array_instead_of_a_string_in_the_email(
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
            session.init(anti_csrf="VIA_TOKEN", cookie_domain="supertokens.io"),
            emailpassword.init(),
        ],
    )
    start_st()

    response_1 = sign_up_request(
        driver_config_client, "random@gmail.com", "validPass123"
    )

    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"

    response_2 = driver_config_client.get(
        url="/auth/signup/email/exists",
        params={"email": ["rAndOM@gmAiL.COm", "x@g.com"]},
    )
    assert response_2.status_code == 200
