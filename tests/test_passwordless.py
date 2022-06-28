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
from fastapi.testclient import TestClient
from pytest import fixture, mark, raises
from supertokens_python import InputAppInfo, SupertokensConfig, init
from supertokens_python.exceptions import GeneralError
from supertokens_python.framework.fastapi import get_middleware
from supertokens_python.querier import Querier
from supertokens_python.recipe import passwordless, session
from supertokens_python.recipe.passwordless.asyncio import (
    delete_email_for_user,
    delete_phone_number_for_user,
    get_user_by_email,
    get_user_by_id,
    get_user_by_phone_number,
    update_user,
)
from supertokens_python.recipe.passwordless.interfaces import (
    DeleteUserInfoOkResult,
    UpdateUserOkResult,
)
from supertokens_python.utils import is_version_gte

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
async def test_passwordless_otp(driver_config_client: TestClient):
    user_input_code = None

    async def send_text_message(
        param: passwordless.CreateAndSendCustomTextMessageParameters, _: Dict[str, Any]
    ):
        nonlocal user_input_code
        user_input_code = param.user_input_code

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
            passwordless.init(
                flow_type="USER_INPUT_CODE",
                contact_config=passwordless.ContactPhoneOnlyConfig(
                    create_and_send_custom_text_message=send_text_message
                ),
            ),
            session.init(),
        ],
    )
    start_st()

    version = await Querier.get_instance().get_api_version()
    if not is_version_gte(version, "2.11"):
        # If the version less than 2.11.0, passwordless OTP doesn't exist. So skip the test
        return

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
    consume_code_json["user"].pop("time_joined")

    assert consume_code_json == {
        "status": "OK",
        "createdNewUser": True,
        "user": {"phoneNumber": "+919494949494"},
    }


@mark.asyncio
async def test_passworldless_delete_user_phone(driver_config_client: TestClient):
    text_code = None
    email_code = None

    async def send_text_message(
        param: passwordless.CreateAndSendCustomTextMessageParameters, _: Dict[str, Any]
    ):
        nonlocal text_code
        text_code = param.user_input_code

    async def send_email(
        param: passwordless.CreateAndSendCustomEmailParameters, _: Dict[str, Any]
    ):
        nonlocal email_code
        email_code = param.user_input_code

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
            passwordless.init(
                flow_type="USER_INPUT_CODE",
                contact_config=passwordless.ContactEmailOrPhoneConfig(
                    create_and_send_custom_text_message=send_text_message,
                    create_and_send_custom_email=send_email,
                ),
            ),
            session.init(),
        ],
    )
    start_st()

    version = await Querier.get_instance().get_api_version()
    if not is_version_gte(version, "2.11"):
        # If the version less than 2.11, passwordless OTP doesn't exist. So skip the test
        return

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

    await update_user(user_id, "foo@example.com", "+919494949494")

    response = await delete_phone_number_for_user(user_id)
    assert isinstance(response, DeleteUserInfoOkResult)

    user = await get_user_by_phone_number("+919494949494")
    assert user is None

    user = await get_user_by_id(user_id)
    assert user is not None and user.phone_number is None


@mark.asyncio
async def test_passworldless_delete_user_email(driver_config_client: TestClient):
    text_code = None
    email_code = None

    async def send_text_message(
        param: passwordless.CreateAndSendCustomTextMessageParameters, _: Dict[str, Any]
    ):
        nonlocal text_code
        text_code = param.user_input_code

    async def send_email(
        param: passwordless.CreateAndSendCustomEmailParameters, _: Dict[str, Any]
    ):
        nonlocal email_code
        email_code = param.user_input_code

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
            passwordless.init(
                flow_type="USER_INPUT_CODE",
                contact_config=passwordless.ContactEmailOrPhoneConfig(
                    create_and_send_custom_text_message=send_text_message,
                    create_and_send_custom_email=send_email,
                ),
            ),
            session.init(),
        ],
    )
    start_st()

    version = await Querier.get_instance().get_api_version()
    if not is_version_gte(version, "2.11"):
        # If the version less than 2.11, passwordless OTP doesn't exist. So skip the test
        return

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

    await update_user(user_id, "hello@example.com", "+919494949494")

    response = await delete_email_for_user(user_id)
    assert isinstance(response, DeleteUserInfoOkResult)

    user = await get_user_by_email("hello@example.com")
    assert user is None

    user = await get_user_by_id(user_id)
    assert user is not None and user.email is None


@mark.asyncio
async def test_passworldless_delete_user_email_and_phone_throws_error(
    driver_config_client: TestClient,
):
    text_code = None
    email_code = None

    async def send_text_message(
        param: passwordless.CreateAndSendCustomTextMessageParameters, _: Dict[str, Any]
    ):
        nonlocal text_code
        text_code = param.user_input_code

    async def send_email(
        param: passwordless.CreateAndSendCustomEmailParameters, _: Dict[str, Any]
    ):
        nonlocal email_code
        email_code = param.user_input_code

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
            passwordless.init(
                flow_type="USER_INPUT_CODE",
                contact_config=passwordless.ContactEmailOrPhoneConfig(
                    create_and_send_custom_text_message=send_text_message,
                    create_and_send_custom_email=send_email,
                ),
            ),
            session.init(),
        ],
    )
    start_st()

    version = await Querier.get_instance().get_api_version()
    if not is_version_gte(version, "2.11"):
        # If the version less than 2.11, passwordless OTP doesn't exist. So skip the test
        return

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

    response = await update_user(user_id, "hello@example.com", "+919494949494")
    assert isinstance(response, UpdateUserOkResult)

    # Delete the email
    response = await delete_email_for_user(user_id)
    # Delete the phone number (Should raise exception because deleting both of them isn't allowed)
    with raises(GeneralError) as e:
        response = await delete_phone_number_for_user(user_id)

    assert e.value.args[0].endswith(
        "You cannot clear both email and phone number of a user\n"
    )
