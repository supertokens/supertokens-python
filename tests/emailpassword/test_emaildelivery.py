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
from typing import Any, Dict
from unittest.mock import MagicMock

import httpx
import respx
from fastapi import FastAPI
from fastapi.requests import Request
from fastapi.testclient import TestClient
from pytest import fixture, mark
from supertokens_python import InputAppInfo, SupertokensConfig, init
from supertokens_python.framework.fastapi import get_middleware
from supertokens_python.ingredients.emaildelivery import EmailDeliveryInterface
from supertokens_python.ingredients.emaildelivery.services.smtp import (
    GetContentResult, ServiceInterface, SMTPServiceConfig,
    SMTPServiceConfigFrom)
from supertokens_python.ingredients.emaildelivery.types import \
    EmailDeliveryConfig
from supertokens_python.recipe import emailpassword, session
from supertokens_python.recipe.emailpassword import (
    InputEmailVerificationConfig, InputResetPasswordUsingTokenFeature)
from supertokens_python.recipe.emailpassword.emaildelivery.services import (
    EmailDeliverySMTPConfig, SMTPService)
from supertokens_python.recipe.emailpassword.types import (
    TypeEmailPasswordEmailDeliveryInput,
    TypeEmailPasswordPasswordResetEmailDeliveryInput)
from supertokens_python.recipe.emailpassword.types import User as EPUser
from supertokens_python.recipe.emailverification.interfaces import \
    TypeEmailVerificationEmailDeliveryInput
from supertokens_python.recipe.session import SessionRecipe
from supertokens_python.recipe.session.recipe_implementation import \
    RecipeImplementation as SessionRecipeImplementation
from supertokens_python.recipe.session.session_functions import \
    create_new_session
from tests.utils import (app_info, clean_st, email_delivery_config,
                         email_verify_token_request, reset,
                         reset_password_request, setup_st, sign_up_request,
                         start_st, supertokens_config)

# respx_mock = respx.MockRouter
respx_mock = MagicMock()

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
    app.add_middleware(get_middleware())

    @app.get('/login')
    async def login(_request: Request):  # type: ignore
        user_id = 'userId'
        # await create_new_session(request, user_id, {}, {})
        return {'userId': user_id}

    return TestClient(app)


@mark.asyncio
async def test_reset_password_default_backward_compatibility(driver_config_client: TestClient):
    "Reset password: test default backward compatibility api being called"
    app_name = ""
    email = ""
    password_reset_url = ""

    init(
        supertokens_config=SupertokensConfig('http://localhost:3567'),
        app_info=InputAppInfo(
            app_name="Demo app testing",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth"
        ),
        framework='fastapi',
        recipe_list=[emailpassword.init(), session.init()]
    )
    start_st()

    sign_up_request(driver_config_client, "shivendu@supertokens.com", "1234abcd")

    def api_side_effect(request: httpx.Request):
        nonlocal app_name, email, password_reset_url
        body = json.loads(request.content)
        app_name = body["appName"]
        email = body["email"]
        password_reset_url = body["passwordResetURL"]
        return httpx.Response(200, json={})

    with respx_mock(assert_all_mocked=False) as mocker:
        mocker.route(host="localhost").pass_through()
        mocked_route = mocker.post("https://api.supertokens.io/0/st/auth/password/reset").mock(side_effect=api_side_effect)
        resp = reset_password_request(driver_config_client, "shivendu@supertokens.com", use_server=True)

@mark.asyncio
async def test_reset_password_smtp_service(driver_config_client: TestClient):
    "Reset password: test smtp service"

    init(
        supertokens_config=SupertokensConfig('http://localhost:3567'),
        app_info=InputAppInfo(
            app_name="Demo app testing",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth"
        ),
        framework='fastapi',
        recipe_list=[emailpassword.init(
            email_delivery=email_delivery_config,
        ), session.init()]
    )
    start_st()

    sign_up_request(driver_config_client, "shivendu@supertokens.com", "1234abcd")
    resp = reset_password_request(driver_config_client, "shivendu@supertokens.com")


# Tests for Email Verification

@mark.asyncio
async def test_email_verification_default_backward_compatibility(driver_config_client: TestClient):
    "Email verification: test default backward compatibility api being called"
    app_name = ""
    email = ""
    email_verify_url = ""

    init(
        supertokens_config=SupertokensConfig('http://localhost:3567'),
        app_info=InputAppInfo(
            app_name="Demo app testing",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth"
        ),
        framework='fastapi',
        recipe_list=[emailpassword.init(), session.init()]
    )
    start_st()


    res = sign_up_request(driver_config_client, "shivendu@supertokens.com", "1234abcd")
    user_id = res.json()['user']['id']

    s = SessionRecipe.get_instance()
    if not isinstance(s.recipe_implementation, SessionRecipeImplementation):
        raise Exception("Should never come here")
    response = await create_new_session(s.recipe_implementation, user_id, {}, {})

    def api_side_effect(request: httpx.Request):
        nonlocal app_name, email, email_verify_url
        body = json.loads(request.content)
        app_name = body["appName"]
        email = body["email"]
        email_verify_url = body["emailVerifyURL"]
        return httpx.Response(200, json={})

    with respx_mock(assert_all_mocked=False) as mocker:
        mocker.route(host="localhost").pass_through()
        # mocker.route(host="https://api.supertokens.io/0/st/auth/email/verify").pass_through()
        mocked_route = mocker.post(
            "https://api.supertokens.io/0/st/auth/email/verify"
        ).mock(side_effect=api_side_effect)
        resp = email_verify_token_request(
            driver_config_client,
            response['accessToken']['token'],
            response['idRefreshToken']['token'],
            response.get('antiCsrf', ""),
            user_id,
            True,
        )


@mark.asyncio
async def test_email_verification_smtp_service(driver_config_client: TestClient):
    "Email verification: test smtp service"

    init(
        supertokens_config=SupertokensConfig('http://localhost:3567'),
        app_info=InputAppInfo(
            app_name="Demo app testing",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth"
        ),
        framework='fastapi',
        recipe_list=[emailpassword.init(
            email_delivery=email_delivery_config
        ), session.init()]
    )
    start_st()

    res = sign_up_request(driver_config_client, "shivendu@supertokens.com", "1234abcd")
    user_id = res.json()['user']['id']

    s = SessionRecipe.get_instance()
    if not isinstance(s.recipe_implementation, SessionRecipeImplementation):
        raise Exception("Should never come here")
    response = await create_new_session(s.recipe_implementation, user_id, {}, {})

    resp = email_verify_token_request(
        driver_config_client,
        response['accessToken']['token'],
        response['idRefreshToken']['token'],
        response.get('antiCsrf', ""),
        user_id,
        True,
    )
