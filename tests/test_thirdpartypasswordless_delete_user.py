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

from pytest import fixture, mark, skip
from supertokens_python import InputAppInfo, SupertokensConfig, init
from supertokens_python.framework.fastapi import get_middleware
from supertokens_python.querier import Querier
from supertokens_python.recipe import passwordless, session, thirdpartypasswordless
from supertokens_python.recipe.passwordless.interfaces import DeleteUserInfoOkResult
from supertokens_python.recipe.passwordless.utils import ContactEmailOrPhoneConfig
from supertokens_python.recipe.thirdpartypasswordless.asyncio import (
    delete_email_for_passwordless_user,
    delete_phone_number_for_user,
    get_user_by_id,
    get_user_by_phone_number,
    get_users_by_email,
    update_passwordless_user,
)
from supertokens_python.utils import is_version_gte

from fastapi import FastAPI
from fastapi.testclient import TestClient
from tests.utils import clean_st, reset, setup_st, start_st


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

    return TestClient(app)


@mark.asyncio
async def test_tp_passworldless_delete_user_info(driver_config_client: TestClient):
    DUMMY_CODE = "DUMMY_CODE"

    async def get_custom_user_input_code(
        _tenant_id: str, _input: Dict[str, Any]
    ) -> str:
        return DUMMY_CODE

    class CustomEmailService(
        passwordless.EmailDeliveryInterface[passwordless.EmailTemplateVars]
    ):
        async def send_email(
            self,
            template_vars: passwordless.EmailTemplateVars,
            user_context: Dict[str, Any],
        ) -> None:
            pass

    class CustomSMSService(
        passwordless.SMSDeliveryInterface[passwordless.SMSTemplateVars]
    ):
        async def send_sms(
            self,
            template_vars: passwordless.SMSTemplateVars,
            user_context: Dict[str, Any],
        ) -> None:
            pass

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
            thirdpartypasswordless.init(
                contact_config=ContactEmailOrPhoneConfig(),
                flow_type="USER_INPUT_CODE_AND_MAGIC_LINK",
                providers=[],
                get_custom_user_input_code=get_custom_user_input_code,
                email_delivery=passwordless.EmailDeliveryConfig(CustomEmailService()),
                sms_delivery=passwordless.SMSDeliveryConfig(CustomSMSService()),
            ),
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
        ],
    )
    start_st()

    version = await Querier.get_instance().get_api_version()
    if not is_version_gte(version, "2.11"):
        # If the version less than 2.11.0, passwordless OTP doesn't exist. So skip the test
        skip()

    create_code_json = driver_config_client.post(
        url="/auth/signinup/code",
        json={
            "phoneNumber": "+919494949494",
        },
    ).json()

    consume_code_json = driver_config_client.post(
        url="/auth/signinup/code/consume",
        json={
            "preAuthSessionId": create_code_json["preAuthSessionId"],
            "deviceId": create_code_json["deviceId"],
            "userInputCode": DUMMY_CODE,
        },
    ).json()

    user_id = consume_code_json["user"]["id"]

    # Update user email as well as phone number
    await update_passwordless_user(
        user_id, email="foo@example.com", phone_number="+919494949494"
    )

    # Check that deleting the user phone number works:
    response = await delete_phone_number_for_user(user_id)
    assert isinstance(response, DeleteUserInfoOkResult)

    user = await get_user_by_phone_number("public", "+919494949494")
    assert user is None

    user = await get_user_by_id(user_id)
    assert user is not None and user.phone_number is None

    # Restore user email and phone number
    await update_passwordless_user(
        user_id, email="foo@example.com", phone_number="+919494949494"
    )

    # Check that deleting the user email works:
    response = await delete_email_for_passwordless_user(user_id)
    assert isinstance(response, DeleteUserInfoOkResult)

    users = await get_users_by_email("public", "foo@example.com")
    assert users == []

    user = await get_user_by_id(user_id)
    assert user is not None and user.email is None
