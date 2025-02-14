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
from pytest import fixture, mark, raises, skip
from supertokens_python import InputAppInfo, SupertokensConfig, init
from supertokens_python.asyncio import get_user, list_users_by_account_info
from supertokens_python.framework.fastapi import get_middleware
from supertokens_python.querier import Querier
from supertokens_python.recipe import passwordless, session
from supertokens_python.recipe.passwordless.asyncio import (
    create_magic_link,
    delete_email_for_user,
    delete_phone_number_for_user,
    update_user,
)
from supertokens_python.recipe.passwordless.interfaces import (
    UpdateUserOkResult,
)
from supertokens_python.types import AccountInfo, RecipeUserId
from supertokens_python.utils import is_version_gte

from tests.testclient import TestClientWithNoCookieJar as TestClient
from tests.utils import get_new_core_app_url


@fixture(scope="function")
def driver_config_client():
    app = FastAPI()
    app.add_middleware(get_middleware())

    return TestClient(app)


@mark.asyncio
async def test_passwordless_otp(driver_config_client: TestClient):
    user_input_code = None

    class CustomSMSService(
        passwordless.SMSDeliveryInterface[passwordless.SMSTemplateVars]
    ):
        async def send_sms(
            self,
            template_vars: passwordless.SMSTemplateVars,
            user_context: Dict[str, Any],
        ) -> None:
            nonlocal user_input_code
            user_input_code = template_vars.user_input_code

    init(
        supertokens_config=SupertokensConfig(get_new_core_app_url()),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth",
        ),
        framework="fastapi",
        recipe_list=[
            passwordless.init(
                flow_type="USER_INPUT_CODE",
                contact_config=passwordless.ContactPhoneOnlyConfig(),
                sms_delivery=passwordless.SMSDeliveryConfig(CustomSMSService()),
            ),
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
        ],
    )

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
            "userInputCode": user_input_code,
        },
    ).json()

    consume_code_json["user"].pop("id")
    consume_code_json["user"].pop("timeJoined")
    consume_code_json["user"]["loginMethods"][0].pop("recipeUserId")
    consume_code_json["user"]["loginMethods"][0].pop("timeJoined")

    assert consume_code_json == {
        "status": "OK",
        "createdNewRecipeUser": True,
        "user": {
            "isPrimaryUser": False,
            "tenantIds": ["public"],
            "emails": [],
            "phoneNumbers": ["+919494949494"],
            "thirdParty": [],
            "loginMethods": [
                {
                    "recipeId": "passwordless",
                    "tenantIds": ["public"],
                    "phoneNumber": "+919494949494",
                    "verified": True,
                }
            ],
        },
    }


@mark.asyncio
async def test_passwordless_create_magic_link(
    driver_config_client: TestClient,  # pylint: disable=unused-argument
):
    init(
        supertokens_config=SupertokensConfig(get_new_core_app_url()),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth",
        ),
        framework="fastapi",
        recipe_list=[
            passwordless.init(
                flow_type="USER_INPUT_CODE",
                contact_config=passwordless.ContactPhoneOnlyConfig(),
            ),
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
        ],
    )

    magic_link = await create_magic_link("public", "test@example.com", None)

    assert "rid=" not in magic_link
    assert "tenantId=public" in magic_link


@mark.asyncio
async def test_passworldless_delete_user_phone(driver_config_client: TestClient):
    text_code = None
    email_code = None

    class CustomEmailService(
        passwordless.EmailDeliveryInterface[passwordless.EmailTemplateVars]
    ):
        async def send_email(
            self,
            template_vars: passwordless.EmailTemplateVars,
            user_context: Dict[str, Any],
        ) -> None:
            nonlocal email_code
            email_code = template_vars.user_input_code

    class CustomSMSService(
        passwordless.SMSDeliveryInterface[passwordless.SMSTemplateVars]
    ):
        async def send_sms(
            self,
            template_vars: passwordless.SMSTemplateVars,
            user_context: Dict[str, Any],
        ) -> None:
            nonlocal text_code
            text_code = template_vars.user_input_code

    init(
        supertokens_config=SupertokensConfig(get_new_core_app_url()),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth",
        ),
        framework="fastapi",
        recipe_list=[
            passwordless.init(
                flow_type="USER_INPUT_CODE",
                contact_config=passwordless.ContactEmailOrPhoneConfig(),
                email_delivery=passwordless.EmailDeliveryConfig(CustomEmailService()),
                sms_delivery=passwordless.SMSDeliveryConfig(CustomSMSService()),
            ),
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
        ],
    )

    version = await Querier.get_instance().get_api_version()
    if not is_version_gte(version, "2.11"):
        # If the version less than 2.11, passwordless OTP doesn't exist. So skip the test
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
            "userInputCode": text_code,
        },
    ).json()

    user_id = consume_code_json["user"]["id"]

    await update_user(RecipeUserId(user_id), "foo@example.com", "+919494949494")

    response = await delete_phone_number_for_user(RecipeUserId(user_id))
    assert isinstance(response, UpdateUserOkResult)

    user = await list_users_by_account_info(
        "public", AccountInfo(phone_number="+919494949494")
    )
    assert len(user) == 0

    user = await get_user(user_id)
    assert user is not None and user.phone_numbers == []


@mark.asyncio
async def test_passworldless_delete_user_email(driver_config_client: TestClient):
    text_code = None
    email_code = None

    class CustomEmailService(
        passwordless.EmailDeliveryInterface[passwordless.EmailTemplateVars]
    ):
        async def send_email(
            self,
            template_vars: passwordless.EmailTemplateVars,
            user_context: Dict[str, Any],
        ) -> None:
            nonlocal email_code
            email_code = template_vars.user_input_code

    class CustomSMSService(
        passwordless.SMSDeliveryInterface[passwordless.SMSTemplateVars]
    ):
        async def send_sms(
            self,
            template_vars: passwordless.SMSTemplateVars,
            user_context: Dict[str, Any],
        ) -> None:
            nonlocal text_code
            text_code = template_vars.user_input_code

    init(
        supertokens_config=SupertokensConfig(get_new_core_app_url()),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth",
        ),
        framework="fastapi",
        recipe_list=[
            passwordless.init(
                flow_type="USER_INPUT_CODE",
                contact_config=passwordless.ContactEmailOrPhoneConfig(),
                email_delivery=passwordless.EmailDeliveryConfig(CustomEmailService()),
                sms_delivery=passwordless.SMSDeliveryConfig(CustomSMSService()),
            ),
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
        ],
    )

    version = await Querier.get_instance().get_api_version()
    if not is_version_gte(version, "2.11"):
        # If the version less than 2.11, passwordless OTP doesn't exist. So skip the test
        skip()

    create_code_json = driver_config_client.post(
        url="/auth/signinup/code",
        json={
            "email": "hello@example.com",
        },
    ).json()

    consume_code_json = driver_config_client.post(
        url="/auth/signinup/code/consume",
        json={
            "preAuthSessionId": create_code_json["preAuthSessionId"],
            "deviceId": create_code_json["deviceId"],
            "userInputCode": email_code,
        },
    ).json()

    user_id = consume_code_json["user"]["id"]

    await update_user(RecipeUserId(user_id), "hello@example.com", "+919494949494")

    response = await delete_email_for_user(RecipeUserId(user_id))
    assert isinstance(response, UpdateUserOkResult)

    user = await list_users_by_account_info(
        "public", AccountInfo(email="hello@example.com")
    )
    assert len(user) == 0

    user = await get_user(user_id)
    assert user is not None and user.emails == []


@mark.asyncio
async def test_passworldless_delete_user_email_and_phone_throws_error(
    driver_config_client: TestClient,
):
    text_code = None
    email_code = None

    class CustomEmailService(
        passwordless.EmailDeliveryInterface[passwordless.EmailTemplateVars]
    ):
        async def send_email(
            self,
            template_vars: passwordless.EmailTemplateVars,
            user_context: Dict[str, Any],
        ) -> None:
            nonlocal email_code
            email_code = template_vars.user_input_code

    class CustomSMSService(
        passwordless.SMSDeliveryInterface[passwordless.SMSTemplateVars]
    ):
        async def send_sms(
            self,
            template_vars: passwordless.SMSTemplateVars,
            user_context: Dict[str, Any],
        ) -> None:
            nonlocal text_code
            text_code = template_vars.user_input_code

    init(
        supertokens_config=SupertokensConfig(get_new_core_app_url()),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth",
        ),
        framework="fastapi",
        recipe_list=[
            passwordless.init(
                flow_type="USER_INPUT_CODE",
                contact_config=passwordless.ContactEmailOrPhoneConfig(),
                email_delivery=passwordless.EmailDeliveryConfig(CustomEmailService()),
                sms_delivery=passwordless.SMSDeliveryConfig(CustomSMSService()),
            ),
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
        ],
    )

    version = await Querier.get_instance().get_api_version()
    if not is_version_gte(version, "2.11"):
        # If the version less than 2.11, passwordless OTP doesn't exist. So skip the test
        skip()

    create_code_json = driver_config_client.post(
        url="/auth/signinup/code",
        json={
            "email": "hello@example.com",
        },
    ).json()

    consume_code_json = driver_config_client.post(
        url="/auth/signinup/code/consume",
        json={
            "preAuthSessionId": create_code_json["preAuthSessionId"],
            "deviceId": create_code_json["deviceId"],
            "userInputCode": email_code,
        },
    ).json()

    user_id = consume_code_json["user"]["id"]

    response = await update_user(
        RecipeUserId(user_id), "hello@example.com", "+919494949494"
    )
    assert isinstance(response, UpdateUserOkResult)

    # Delete the email
    response = await delete_email_for_user(RecipeUserId(user_id))
    # Delete the phone number (Should raise exception because deleting both of them isn't allowed)
    with raises(Exception) as e:
        response = await delete_phone_number_for_user(RecipeUserId(user_id))

    assert e.value.args[0].endswith(
        "You cannot clear both email and phone number of a user\n"
    )
