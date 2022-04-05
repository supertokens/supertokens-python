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

from typing import Any, Dict

from fastapi import FastAPI
from fastapi.requests import Request
from fastapi.testclient import TestClient
from pytest import fixture, mark
from supertokens_python import InputAppInfo, SupertokensConfig, init
from supertokens_python.framework.fastapi import Middleware
from supertokens_python.recipe import emailpassword, session
from supertokens_python.recipe.emailpassword import utils
from supertokens_python.recipe.emailpassword.types import User

from tests.utils import clean_st, reset, setup_st, sign_up_request, start_st
import json


def setup_function(_):
    reset()
    clean_st()
    setup_st()


def teardown_function(_):
    reset()
    clean_st()


@fixture(scope='function')
async def driver_config_client():
    app = FastAPI()
    app.add_middleware(Middleware)

    @app.get('/login')
    async def login(request: Request):  # type: ignore
        user_id = 'userId'
        await create_new_session(request, user_id, {}, {})
        return {'userId': user_id}

    return TestClient(app)


@mark.asyncio
async def test_that_once_email_delivery_works(driver_config_client: TestClient):
    async def create_and_send_custom_email(user: User, some: str, user_context: Dict[str, Any]):
        pass

    email_verification_feature = utils.InputEmailVerificationConfig(
        create_and_send_custom_email=create_and_send_custom_email
    )

    init(
        supertokens_config=SupertokensConfig('http://localhost:3567'),
        app_info=InputAppInfo(
            app_name='SuperTokens Demo',
            api_domain='https://api.supertokens.io',
            website_domain='supertokens.io'
        ),
        framework='fastapi',
        recipe_list=[emailpassword.init(email_verification_feature=email_verification_feature), session.init()],
    )
    start_st()

    sign_up_request(driver_config_client, "test@gmail.com", "testPass123")


@mark.asyncio
async def test_something(driver_config_client: TestClient):
    async def create_and_send_custom_email(user: User, some: str, user_context: Dict[str, Any]):
        pass

    email_verification_feature = utils.InputEmailVerificationConfig(
        create_and_send_custom_email=create_and_send_custom_email
    )

    init(
        supertokens_config=SupertokensConfig('http://localhost:3567'),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth"
        ),
        framework='fastapi',
        recipe_list=[emailpassword.init(email_verification_feature=email_verification_feature), session.init()]
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

    response_2 = driver_config_client.post(url="/auth/user/email/verify/token")
