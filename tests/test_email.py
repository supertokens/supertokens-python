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


from supertokens_python.recipe.emailpassword.emaildelivery.service.smtp import (
    EmailDeliverySMTPConfig, SMTPService)
from unittest.mock import MagicMock, patch

from fastapi import FastAPI
from fastapi.requests import Request
from fastapi.testclient import TestClient
from pytest import fixture, mark
from supertokens_python import InputAppInfo, SupertokensConfig, init
from supertokens_python.framework.fastapi import Middleware
from supertokens_python.ingredients.emaildelivery.service.smtp import \
    SMTPServiceConfig
from supertokens_python.ingredients.emaildelivery.types import \
    EmailDeliveryConfig
from supertokens_python.recipe import emailpassword, session

from tests.utils import clean_st, reset, setup_st, sign_up_request, start_st


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
        # await create_new_session(request, user_id, {}, {})
        return {'userId': user_id}

    return TestClient(app)


@mark.asyncio
@patch("supertokens_python.recipe.emailverification.emaildelivery.service.backwardCompatibility.default_create_and_send_custom_email")
async def test_email_verification_email_delivery_backward_compatibility(mock_default_create_and_send_custom_email: MagicMock, driver_config_client: TestClient):
    mock_create_and_send_custom_email = mock_default_create_and_send_custom_email.return_value = MagicMock()

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

    sign_up_request(
        driver_config_client,
        "random@gmail.com",
        "validpass123"
    )

    driver_config_client.post(
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
                }]
        }
    )

    # Send email verification email to the user with the default default method (backwardCompatibility)
    resp = driver_config_client.post(url="/auth/user/email/verify/token")
    assert resp.status_code == 200
    mock_create_and_send_custom_email.assert_called_once()


@mark.asyncio
@patch("supertokens_python.recipe.emailpassword.utils.default_create_and_send_custom_email")
async def test_email_password_email_delivery_backward_compatibility(mock_default_create_and_send_custom_email: MagicMock, driver_config_client: TestClient):
    mock_create_and_send_custom_email = mock_default_create_and_send_custom_email.return_value = MagicMock()

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

    sign_up_request(
        driver_config_client,
        "random@gmail.com",
        "validpass123"
    )

    res = driver_config_client.post(
        url="/auth/user/password/reset/token",
        json={
            'formFields':
                [{
                    "id": "email",
                    "value": "random@gmail.com"
                }]
        }
    )
    assert res.status_code == 200

    # Send password reset email to the user with the default method (backwardCompatibility)
    mock_create_and_send_custom_email.assert_called_once()


@mark.asyncio
async def test_email_password_email_delivery_smtp(driver_config_client: TestClient):
    service = SMTPService(
        EmailDeliverySMTPConfig(
            smtpSettings=SMTPServiceConfig(
                host='0.0.0.0',
                email_from=SMTPServiceConfigFrom(
                    'Kumar Shivendu',
                    "shivendu@it.com"
                ),
                port=5000,
            )
        )
    )
    emc = EmailDeliveryConfig(service, override=None)

    init(
        supertokens_config=SupertokensConfig('http://localhost:3567'),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth"
        ),
        framework='fastapi',
        recipe_list=[
            emailpassword.init(email_delivery=emc),
            session.init()
        ]
    )
    start_st()

    sign_up_request(
        driver_config_client,
        "random@gmail.com",
        "validpass123"
    )

    res = driver_config_client.post(
        url="/auth/user/password/reset/token",
        json={
            'formFields':
                [{
                    "id": "email",
                    "value": "random@gmail.com"
                }]
        }
    )
    assert res.status_code == 200
