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
from supertokens_python.ingredients.emaildelivery.services.smtp import (
    EmailDeliverySMTPConfig, GetContentResult, ServiceInterface,
    SMTPServiceConfig, SMTPServiceConfigFrom)
from supertokens_python.ingredients.emaildelivery.types import (
    EmailDeliveryConfig, EmailDeliveryInterface)
from supertokens_python.recipe import (passwordless, session,
                                       thirdpartypasswordless)
from supertokens_python.recipe.emailverification.interfaces import \
    CreateEmailVerificationTokenEmailAlreadyVerifiedError
from supertokens_python.recipe.passwordless import ContactEmailOnlyConfig
from supertokens_python.recipe.passwordless.types import \
    TypePasswordlessEmailDeliveryInput
from supertokens_python.recipe.session import SessionRecipe
from supertokens_python.recipe.session.recipe_implementation import \
    RecipeImplementation as SessionRecipeImplementation
from supertokens_python.recipe.session.session_functions import \
    create_new_session
from supertokens_python.recipe.thirdparty.types import \
    TypeThirdPartyEmailDeliveryInput
from supertokens_python.recipe.thirdpartypasswordless.asyncio import (
    create_email_verification_token, passwordlessSigninup,
    thirdparty_sign_in_up)
from supertokens_python.recipe.thirdpartypasswordless.emaildelivery.services.smtp import \
    SMTPService
from supertokens_python.recipe.thirdpartypasswordless.interfaces import \
    ThirdPartySignInUpOkResult
from supertokens_python.recipe.thirdpartypasswordless.types import (
    TypeThirdPartyPasswordlessEmailDeliveryInput, User)
from tests.utils import (app_info, clean_st, email_delivery_smtp_config,
                         email_verify_token_request, reset, setup_st,
                         sign_in_up_request, sms_delivery_twilio_config,
                         start_st, supertokens_config)

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
async def test_email_verify_default_backward_compatibility(driver_config_client: TestClient):
    "Email verify: test default backward compatibility api being called"

    init(
        supertokens_config=SupertokensConfig('http://localhost:3567'),
        app_info=InputAppInfo(
            app_name="Demo app testing",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth"
        ),
        framework='fastapi',
        recipe_list=[thirdpartypasswordless.init(
            contact_config=ContactEmailOnlyConfig(),
            flow_type='USER_INPUT_CODE_AND_MAGIC_LINK',
            providers=[],
        ), session.init()]
    )
    start_st()

    resp = await thirdparty_sign_in_up("supertokens", "test-user-id", "shivendu@supertokens.com", False)

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
        recipe_list=[thirdpartypasswordless.init(
            contact_config=ContactEmailOnlyConfig(),
            flow_type='USER_INPUT_CODE_AND_MAGIC_LINK',
            providers=[],
            email_delivery=EmailDeliveryConfig(
                service=email_delivery_service,
            )
        ), session.init()]
    )
    start_st()
    

    resp = await thirdparty_sign_in_up("supertokens", "test-user-id", "shivendu@supertokens.com", False)

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


@mark.asyncio
async def test_pless_login_default_backward_compatibility(driver_config_client: TestClient):
    "Passwordless login: test default backward compatibility api being called"
    init(
        supertokens_config=SupertokensConfig('http://localhost:3567'),
        app_info=InputAppInfo(
            app_name="Demo app testing",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth"
        ),
        framework='fastapi',
        recipe_list=[thirdpartypasswordless.init(
            contact_config=passwordless.ContactEmailOnlyConfig(),
            flow_type="USER_INPUT_CODE_AND_MAGIC_LINK",
        ), session.init()]
    )
    start_st()
    

    resp = sign_in_up_request(driver_config_client, "shivendu@supertokens.com", True)


@mark.asyncio
async def test_pless_login_smtp_service(driver_config_client: TestClient):
    "Passwordless login: test smtp service"

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
        recipe_list=[thirdpartypasswordless.init(
            contact_config=passwordless.ContactEmailOnlyConfig(),
            flow_type="USER_INPUT_CODE_AND_MAGIC_LINK",
            email_delivery=EmailDeliveryConfig(
                service=email_delivery_service,
                override=None,
            ),
        ), session.init()]
    )
    start_st()
    

    resp = sign_in_up_request(driver_config_client, "shivendu@supertokens.com", True)
