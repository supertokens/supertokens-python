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

from fastapi import FastAPI
from fastapi.requests import Request
from fastapi.testclient import TestClient
from pytest import fixture
from pytest import mark

from supertokens_python import init, SupertokensConfig, InputAppInfo
from supertokens_python.recipe import session, emailpassword
from supertokens_python.recipe.emailpassword.interfaces import APIInterface
from supertokens_python.framework.fastapi import Middleware
from supertokens_python.recipe.session.asyncio import create_new_session, refresh_session, get_session
from tests.utils import (
    reset, setup_st, clean_st, start_st, sign_up_request, extract_all_cookies
)


def setup_function(f):
    reset()
    clean_st()
    setup_st()


def teardown_function(f):
    reset()
    clean_st()


@fixture(scope='function')
async def driver_config_client():
    app = FastAPI()
    app.add_middleware(Middleware)

    @app.get('/login')
    async def login(request: Request):
        user_id = 'userId'
        await create_new_session(request, user_id, {}, {})
        return {'userId': user_id}

    @app.post('/refresh')
    async def custom_refresh(request: Request):
        await refresh_session(request)
        return {}

    @app.get('/info')
    async def info_get(request: Request):
        await get_session(request, True)
        return {}

    @app.get('/custom/info')
    def custom_info(_):
        return {}

    @app.options('/custom/handle')
    def custom_handle_options(_):
        return {'method': 'option'}

    @app.get('/handle')
    async def handle_get(request: Request):
        session = await get_session(request, True)
        return {'s': session.get_handle()}

    @app.post('/logout')
    async def custom_logout(request: Request):
        session = await get_session(request, True)
        await session.revoke_session()
        return {}

    return TestClient(app)


@mark.asyncio
async def test_that_disabling_api_the_default_signin_API_does_not_work(driver_config_client: TestClient):
    def apis_override_email_password(param: APIInterface):
        param.disable_sign_in_post = True
        return param

    init(
        supertokens_config=SupertokensConfig('http://localhost:3567'),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth"
        ),
        framework='fastapi',
        recipe_list=[emailpassword.init(
            override=emailpassword.InputOverrideConfig(
                apis=apis_override_email_password
            )
        )]
    )
    start_st()

    response_1 = driver_config_client.post(
        url="/auth/signin",
        json={
            'formFields':
                [{
                    "id": "password",
                    "value": "validpass123"
                },
                    {
                        "id": "email",
                        "value": "random@gmail.com"
                }
                ]
        })

    assert response_1.status_code == 404


@mark.asyncio
async def test_singinAPI_works_when_input_is_fine(driver_config_client: TestClient):
    init(
        supertokens_config=SupertokensConfig('http://localhost:3567'),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth"
        ),
        framework='fastapi',
        recipe_list=[emailpassword.init(), session.init()]
    )
    start_st()

    response_1 = sign_up_request(
        driver_config_client,
        "random@gmail.com",
        "validpass123")
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    user_info = dict_response['user']
    assert dict_response["status"] == "OK"

    response_2 = driver_config_client.post(
        url="/auth/signin",
        json={
            'formFields':
                [{
                    "id": "password",
                    "value": "validpass123"
                },
                    {
                        "id": "email",
                        "value": "random@gmail.com"
                }
                ]
        })

    assert response_2.status_code == 200
    dict_response = json.loads(response_2.text)
    assert dict_response['user']['id'] == user_info['id']
    assert dict_response['user']['email'] == user_info['email']


@mark.asyncio
async def test_singinAPI_throws_an_error_when_email_does_not_match(driver_config_client: TestClient):
    init(
        supertokens_config=SupertokensConfig('http://localhost:3567'),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth"
        ),
        framework='fastapi',
        recipe_list=[emailpassword.init(), session.init()]
    )
    start_st()

    response_1 = sign_up_request(
        driver_config_client,
        "random@gmail.com",
        "validpass123")
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"

    response_2 = driver_config_client.post(
        url="/auth/signin",
        json={
            'formFields':
                [{
                    "id": "password",
                    "value": "validpass123"
                },
                    {
                        "id": "email",
                        "value": "ra@gmail.com"
                }
                ]
        })

    assert response_2.status_code == 200
    dict_response = json.loads(response_2.text)
    assert dict_response['status'] == 'WRONG_CREDENTIALS_ERROR'


@mark.asyncio
async def test_singin_api_throws_an_error_when_email_does_not_match(driver_config_client: TestClient):
    init(
        supertokens_config=SupertokensConfig('http://localhost:3567'),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth"
        ),
        framework='fastapi',
        recipe_list=[emailpassword.init(), session.init()]
    )
    start_st()

    response_1 = sign_up_request(
        driver_config_client,
        "random@gmail.com",
        "validpass123")
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"

    response_2 = driver_config_client.post(
        url="/auth/signin",
        json={
            'formFields':
                [{
                    "id": "password",
                    "value": "validpass123"
                },
                    {
                        "id": "email",
                        "value": "ra@gmail.com"
                }
                ]
        })

    assert response_2.status_code == 200
    dict_response = json.loads(response_2.text)
    assert dict_response['status'] == 'WRONG_CREDENTIALS_ERROR'


@mark.asyncio
async def test_singinAPI_throws_an_error_if_password_is_incorrect(driver_config_client: TestClient):
    init(
        supertokens_config=SupertokensConfig('http://localhost:3567'),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth"
        ),
        framework='fastapi',
        recipe_list=[emailpassword.init(), session.init()]
    )
    start_st()

    response_1 = sign_up_request(
        driver_config_client,
        "random@gmail.com",
        "validpass123")
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"

    response_2 = driver_config_client.post(
        url="/auth/signin",
        json={
            'formFields':
                [{
                    "id": "password",
                    "value": "wrong_password"
                },
                    {
                        "id": "email",
                        "value": "random@gmail.com"
                }
                ]
        })

    assert response_2.status_code == 200
    dict_response = json.loads(response_2.text)
    assert dict_response['status'] == 'WRONG_CREDENTIALS_ERROR'


@mark.asyncio
async def test_bad_input_not_a_JSON_to_signin_api(driver_config_client: TestClient):
    init(
        supertokens_config=SupertokensConfig('http://localhost:3567'),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth"
        ),
        framework='fastapi',
        recipe_list=[emailpassword.init(), session.init()]
    )
    start_st()

    response_1 = sign_up_request(
        driver_config_client,
        "random@gmail.com",
        "validpass123")
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"

    response_2 = driver_config_client.post(
        url="/auth/signin",
        json={
            'x': 'y'
        })

    assert response_2.status_code == 400
    dict_response = json.loads(response_2.text)
    assert dict_response['message'] == 'Are you sending too many / too few formFields?'


@mark.asyncio
async def test_bad_input_not_a_JSON_to_signin_API(driver_config_client: TestClient):
    init(
        supertokens_config=SupertokensConfig('http://localhost:3567'),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth"
        ),
        framework='fastapi',
        recipe_list=[emailpassword.init(), session.init()]
    )
    start_st()

    response_1 = sign_up_request(
        driver_config_client,
        "random@gmail.com",
        "validpass123")
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"

    response_2 = driver_config_client.post(
        url="/auth/signin",
        json={
            'x': 'y'
        })

    assert response_2.status_code == 400
    dict_response = json.loads(response_2.text)
    assert dict_response['message'] == 'Are you sending too many / too few formFields?'


@mark.asyncio
async def test_that_a_successful_signin_yields_a_session(driver_config_client: TestClient):
    init(
        supertokens_config=SupertokensConfig('http://localhost:3567'),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth"
        ),
        framework='fastapi',
        recipe_list=[emailpassword.init(), session.init(
            anti_csrf='VIA_TOKEN'
        )]
    )
    start_st()

    response_1 = sign_up_request(
        driver_config_client,
        "random@gmail.com",
        "validpass123")
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"

    response_2 = driver_config_client.post(
        url="/auth/signin",
        json={
            'formFields':
                [{
                    "id": "password",
                    "value": "validpass123"
                },
                    {
                        "id": "email",
                        "value": "random@gmail.com"
                }
                ]
        })

    assert response_2.status_code == 200

    cookies = extract_all_cookies(response_1)

    assert (cookies["sAccessToken"] is not None)
    assert (cookies['sRefreshToken'] is not None)
    assert response_2.headers.get('anti-csrf') is not None
    assert (cookies["sIdRefreshToken"] is not None)


@mark.asyncio
async def test_email_field_validation_error(
        driver_config_client: TestClient):
    init(
        supertokens_config=SupertokensConfig('http://localhost:3567'),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth"
        ),
        framework='fastapi',
        recipe_list=[emailpassword.init(), session.init()]
    )
    start_st()

    response_1 = sign_up_request(
        driver_config_client,
        "random@gmail.com",
        "validpassword123")
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"

    response_2 = driver_config_client.post(
        url="/auth/signin",
        json={
            'formFields':
                [{
                    "id": "password",
                    "value": "validpassword123"
                },
                    {
                        "id": "email",
                        "value": "randomgmail.com"
                }
                ]
        })

    assert response_2.status_code == 200
    dict_response = json.loads(response_2.text)
    assert dict_response['status'] == 'FIELD_ERROR'


@mark.asyncio
async def test_formFields_has_no_email_field(
        driver_config_client: TestClient):
    init(
        supertokens_config=SupertokensConfig('http://localhost:3567'),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth"
        ),
        framework='fastapi',
        recipe_list=[emailpassword.init(), session.init()]
    )
    start_st()

    response_1 = sign_up_request(
        driver_config_client,
        "random@gmail.com",
        "validpassword123")
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"

    response_2 = driver_config_client.post(
        url="/auth/signin",
        json={
            'formFields':
                [{
                    "id": "password",
                    "value": "validpassword123"
                }
                ]
        })

    assert response_2.status_code == 400


@mark.asyncio
async def test_formFields_has_no_password_field(
        driver_config_client: TestClient):
    init(
        supertokens_config=SupertokensConfig('http://localhost:3567'),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth"
        ),
        framework='fastapi',
        recipe_list=[emailpassword.init(), session.init()]
    )
    start_st()

    response_1 = sign_up_request(
        driver_config_client,
        "random@gmail.com",
        "validpassword123")
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"

    response_2 = driver_config_client.post(
        url="/auth/signin",
        json={
            'formFields':
                [{
                    "id": "email",
                    "value": "randomgmail.com"
                }
                ]
        })

    assert response_2.status_code == 400

# TODO add few more tests
