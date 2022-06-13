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
from unittest.mock import MagicMock

import httpx
import respx
from fastapi import FastAPI
from fastapi.requests import Request
from fastapi.testclient import TestClient
from pytest import fixture, mark
from supertokens_python import InputAppInfo, SupertokensConfig, init
from supertokens_python.framework.fastapi import get_middleware
from supertokens_python.ingredients.emaildelivery.services.smtp import (
    EmailDeliverySMTPConfig, GetContentResult, ServiceInterface,
    SMTPServiceConfig, SMTPServiceConfigFrom)
from supertokens_python.ingredients.emaildelivery.types import (
    EmailDeliveryConfig, EmailDeliveryInterface)
from supertokens_python.recipe import session, thirdparty
from supertokens_python.recipe.session import SessionRecipe
from supertokens_python.recipe.session.recipe_implementation import \
    RecipeImplementation as SessionRecipeImplementation
from supertokens_python.recipe.session.session_functions import \
    create_new_session
from supertokens_python.recipe.thirdparty.asyncio import sign_in_up
from supertokens_python.recipe.thirdparty.emaildelivery.services.smtp import \
    SMTPService
from supertokens_python.recipe.thirdparty.interfaces import SignInUpOkResult
from supertokens_python.recipe.thirdparty.provider import Provider
from supertokens_python.recipe.thirdparty.types import (
    AccessTokenAPI, AuthorisationRedirectAPI, TypeThirdPartyEmailDeliveryInput,
    User, UserInfo, UserInfoEmail)
from tests.utils import (clean_st, email_delivery_smtp_config,
                         email_verify_token_request, reset, setup_st, start_st)

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


class CustomProvider(Provider):
    async def get_profile_info(self, auth_code_response: Dict[str, Any], user_context: Dict[str, Any]) -> UserInfo:
        return UserInfo(
            user_id=auth_code_response["id"],
            email=UserInfoEmail(auth_code_response["email"], True)
        )

    def get_authorisation_redirect_api_info(self, user_context: Dict[str, Any]) -> AuthorisationRedirectAPI:
        return AuthorisationRedirectAPI("https://example.com/oauth/auth", {})

    def get_access_token_api_info(self, redirect_uri: str, auth_code_from_request: str, user_context: Dict[str, Any]) -> AccessTokenAPI:
        return AccessTokenAPI("https://example.com/oauth/token", {})

    def get_redirect_uri(self, user_context: Dict[str, Any]) -> Union[None, str]:
        return

    def get_client_id(self, user_context: Dict[str, Any]) -> str:
        return "foo"


@mark.asyncio
async def test_email_verify_default_backward_compatibility(driver_config_client: TestClient):
    "Email verify: test default backward compatibility api being called"
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
        recipe_list=[thirdparty.init(
            sign_in_and_up_feature=thirdparty.SignInAndUpFeature(providers=[
                CustomProvider("CUSTOM", True)
            ])
        ), session.init()]
    )
    start_st()
    

    resp = await sign_in_up("supertokens", "test-user-id", "shivendu@supertokens.com", False)

    s = SessionRecipe.get_instance()
    if not isinstance(s.recipe_implementation, SessionRecipeImplementation):
        raise Exception("Should never come here")
    
    user_id = resp.user.user_id
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
async def test_email_verify_smtp_service(driver_config_client: TestClient):
    "Email verify: test smtp service"
    email_delivery_service = SMTPService(
        config=email_delivery_smtp_config
    )

    init(
        supertokens_config=SupertokensConfig('http://localhost:3567'),
        app_info=InputAppInfo(
            app_name="Demo app testing",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth"
        ),
        framework='fastapi',
        recipe_list=[
            thirdparty.init(
                sign_in_and_up_feature=thirdparty.SignInAndUpFeature(providers=[
                    CustomProvider("CUSTOM", True)
                ]),
                email_delivery=EmailDeliveryConfig(
                    service=email_delivery_service,
                ),
            ), session.init()]
    )
    start_st()
    

    resp = await sign_in_up("supertokens", "test-user-id", "shivendu@supertokens.com", False)

    s = SessionRecipe.get_instance()
    if not isinstance(s.recipe_implementation, SessionRecipeImplementation):
        raise Exception("Should never come here")
    
    user_id = resp.user.user_id
    
    response = await create_new_session(s.recipe_implementation, user_id, {}, {})

    resp = email_verify_token_request(
        driver_config_client,
        response['accessToken']['token'],
        response['idRefreshToken']['token'],
        response.get('antiCsrf', ""),
        user_id,
        True,
    )
