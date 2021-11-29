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
import asyncio
import json

from fastapi import FastAPI
from fastapi.requests import Request
from fastapi.testclient import TestClient
from pytest import fixture
from pytest import mark

from supertokens_python import init, SupertokensConfig, InputAppInfo
from supertokens_python.recipe import session, emailpassword
from supertokens_python.recipe.emailpassword.asyncio import revoke_email_verification_token, verify_email_using_token, \
    create_email_verification_token, is_email_verified, unverify_email
from supertokens_python.recipe.emailverification.interfaces import APIInterface, APIOptions
from supertokens_python.exceptions import BadInputError
from supertokens_python.framework.fastapi import Middleware
from supertokens_python.querier import Querier
from supertokens_python.recipe.session.asyncio import create_new_session, refresh_session, get_session
from tests.utils import (
    reset, setup_st, clean_st, start_st, sign_up_request, extract_all_cookies, email_verify_token_request,
    set_key_value_in_config, TEST_ACCESS_TOKEN_MAX_AGE_CONFIG_KEY
)
from supertokens_python.recipe.emailverification.utils import OverrideConfig


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
async def test_the_generate_token_api_with_valid_input_email_not_verified(driver_config_client: TestClient):
    init(
        supertokens_config=SupertokensConfig('http://localhost:3567'),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth"
        ),
        framework='fastapi',
        recipe_list=[session.init(
            anti_csrf='VIA_TOKEN'
        ), emailpassword.init()]
    )
    start_st()

    response_1 = sign_up_request(
        driver_config_client,
        "test@gmail.com",
        "testPass123")

    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"

    user_id = dict_response["user"]["id"]
    cookies = extract_all_cookies(response_1)

    response = email_verify_token_request(driver_config_client, cookies['sAccessToken']['value'],
                                          cookies['sIdRefreshToken']['value'], response_1.headers.get(
                                              'anti-csrf'),
                                          user_id)
    dict_response = json.loads(response.text)
    assert dict_response["status"] == "OK"


@mark.asyncio
async def test_the_generate_token_api_with_valid_input_email_verified_and_test_error(driver_config_client: TestClient):
    init(
        supertokens_config=SupertokensConfig('http://localhost:3567'),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth"
        ),
        framework='fastapi',
        recipe_list=[session.init(
            anti_csrf='VIA_TOKEN'
        ), emailpassword.init()]
    )
    start_st()

    response_1 = sign_up_request(
        driver_config_client,
        "test@gmail.com",
        "testPass123")

    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"

    user_id = dict_response["user"]["id"]
    cookies = extract_all_cookies(response_1)

    verify_token = await create_email_verification_token(user_id)
    await verify_email_using_token(verify_token.token)

    response = email_verify_token_request(driver_config_client, cookies['sAccessToken']['value'],
                                          cookies['sIdRefreshToken']['value'], response_1.headers.get(
                                              'anti-csrf'),
                                          user_id)
    dict_response = json.loads(response.text)
    assert dict_response["status"] == "EMAIL_ALREADY_VERIFIED_ERROR"


@mark.asyncio
async def test_the_generate_token_api_with_valid_input_no_session_and_check_output(driver_config_client: TestClient):
    init(
        supertokens_config=SupertokensConfig('http://localhost:3567'),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth"
        ),
        framework='fastapi',
        recipe_list=[session.init(
            anti_csrf='VIA_TOKEN'
        ), emailpassword.init()]
    )
    start_st()

    response_1 = driver_config_client.post(url='/auth/user/email/verify/token')
    assert response_1.status_code == 401
    dict_response = json.loads(response_1.text)
    assert dict_response["message"] == "unauthorised"


@mark.asyncio
async def test_the_generate_token_api_with_an_expired_access_token_and_see_that_try_refresh_token_is_returned(
        driver_config_client: TestClient):
    set_key_value_in_config(
        TEST_ACCESS_TOKEN_MAX_AGE_CONFIG_KEY,
        2)

    init(
        supertokens_config=SupertokensConfig('http://localhost:3567'),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth"
        ),
        framework='fastapi',
        recipe_list=[session.init(
            anti_csrf='VIA_TOKEN'
        ), emailpassword.init()]
    )
    start_st()

    response_1 = sign_up_request(
        driver_config_client,
        "test@gmail.com",
        "testPass123")
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"
    user_id = dict_response["user"]["id"]

    cookies = extract_all_cookies(response_1)

    await asyncio.sleep(5)

    response_2 = email_verify_token_request(driver_config_client, cookies['sAccessToken']['value'],
                                            cookies['sIdRefreshToken']['value'], response_1.headers.get(
                                                'anti-csrf'),
                                            user_id)
    dict_response = json.loads(response_2.text)

    assert response_2.status_code == 401
    assert dict_response['message'] == 'try refresh token'

    response_3 = driver_config_client.post(
        url="/auth/session/refresh",
        headers={
            "Content-Type": "application/json",
            'anti-csrf': response_1.headers.get('anti-csrf')
        },
        cookies={
            'sRefreshToken': cookies['sRefreshToken']['value'],
            'sIdRefreshToken': cookies['sIdRefreshToken']['value'],
        })

    assert response_3.status_code == 200

    cookies1 = extract_all_cookies(response_3)
    response_4 = email_verify_token_request(driver_config_client, cookies1['sAccessToken']['value'],
                                            cookies1['sIdRefreshToken']['value'], response_3.headers.get(
                                                'anti-csrf'),
                                            user_id)

    dict_response = json.loads(response_4.text)

    assert response_4.status_code == 200
    assert dict_response['status'] == 'OK'


@mark.asyncio
async def test_that_providing_your_own_email_callback_and_make_sure_it_is_called(driver_config_client: TestClient):
    user_info = None
    email_token = None

    async def custom_f(user, email_verification_url_token):
        nonlocal user_info, email_token
        user_info = user
        email_token = email_verification_url_token

    init(
        supertokens_config=SupertokensConfig('http://localhost:3567'),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth"
        ),
        framework='fastapi',
        recipe_list=[session.init(
            anti_csrf='VIA_TOKEN'
        ), emailpassword.init(
            email_verification_feature=emailpassword.InputEmailVerificationConfig(
                create_and_send_custom_email=custom_f
            )
        )]
    )
    start_st()

    response_1 = sign_up_request(
        driver_config_client,
        "test@gmail.com",
        "testPass123")
    await asyncio.sleep(1)
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"
    user_id = dict_response["user"]["id"]

    cookies = extract_all_cookies(response_1)

    response_2 = email_verify_token_request(driver_config_client, cookies['sAccessToken']['value'],
                                            cookies['sIdRefreshToken']['value'], response_1.headers.get(
                                                'anti-csrf'),
                                            user_id)
    await asyncio.sleep(2)

    dict_response = json.loads(response_2.text)
    assert dict_response['status'] == 'OK'

    assert user_info.user_id == user_id
    assert user_info.email == "test@gmail.com"
    assert email_token is not None


@mark.asyncio
async def test_the_email_verify_api_with_valid_input(driver_config_client: TestClient):
    token = None

    async def custom_f(user, email_verification_url_token):
        nonlocal token
        token = email_verification_url_token.split(
            "?token=")[1].split("&ride")[0]

    init(
        supertokens_config=SupertokensConfig('http://localhost:3567'),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth"
        ),
        framework='fastapi',
        recipe_list=[session.init(
            anti_csrf='VIA_TOKEN'
        ), emailpassword.init(
            email_verification_feature=emailpassword.InputEmailVerificationConfig(
                create_and_send_custom_email=custom_f
            )
        )]
    )
    start_st()

    response_1 = sign_up_request(
        driver_config_client,
        "test@gmail.com",
        "testPass123")
    await asyncio.sleep(1)
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"
    user_id = dict_response["user"]["id"]

    cookies = extract_all_cookies(response_1)

    response_2 = email_verify_token_request(driver_config_client, cookies['sAccessToken']['value'],
                                            cookies['sIdRefreshToken']['value'], response_1.headers.get(
                                                'anti-csrf'),
                                            user_id)
    await asyncio.sleep(2)

    dict_response = json.loads(response_2.text)
    assert dict_response['status'] == 'OK'

    assert token is not None

    response_3 = driver_config_client.post(
        url="/auth/user/email/verify",
        headers={
            "Content-Type": "application/json",
            'anti-csrf': response_1.headers.get('anti-csrf')
        },
        cookies={
            'sRefreshToken': cookies['sRefreshToken']['value'],
            'sIdRefreshToken': cookies['sIdRefreshToken']['value'],
        },
        json={
            "method": "token",
            "token": token
        }
    )

    dict_response = json.loads(response_3.text)
    assert dict_response['status'] == 'OK'


@mark.asyncio
async def test_the_email_verify_api_with_invalid_token_and_check_error(driver_config_client: TestClient):
    token = None

    async def custom_f(user, email_verification_url_token):
        nonlocal token
        token = email_verification_url_token.split(
            "?token=")[1].split("&ride")[0]

    init(
        supertokens_config=SupertokensConfig('http://localhost:3567'),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth"
        ),
        framework='fastapi',
        recipe_list=[session.init(
            anti_csrf='VIA_TOKEN'
        ), emailpassword.init(
            email_verification_feature=emailpassword.InputEmailVerificationConfig(
                create_and_send_custom_email=custom_f
            )
        )]
    )
    start_st()

    response_1 = sign_up_request(
        driver_config_client,
        "test@gmail.com",
        "testPass123")
    await asyncio.sleep(1)
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"
    user_id = dict_response["user"]["id"]

    cookies = extract_all_cookies(response_1)

    response_2 = email_verify_token_request(driver_config_client, cookies['sAccessToken']['value'],
                                            cookies['sIdRefreshToken']['value'], response_1.headers.get(
                                                'anti-csrf'),
                                            user_id)
    await asyncio.sleep(2)

    dict_response = json.loads(response_2.text)
    assert dict_response['status'] == 'OK'

    assert token is not None

    response_3 = driver_config_client.post(
        url="/auth/user/email/verify",
        headers={
            "Content-Type": "application/json",
            'anti-csrf': response_1.headers.get('anti-csrf')
        },
        cookies={
            'sRefreshToken': cookies['sRefreshToken']['value'],
            'sIdRefreshToken': cookies['sIdRefreshToken']['value'],
        },
        json={
            "method": "token",
            "token": "bad token"
        }
    )

    dict_response = json.loads(response_3.text)
    assert dict_response['status'] == 'EMAIL_VERIFICATION_INVALID_TOKEN_ERROR'


@mark.asyncio
async def test_the_email_verify_api_with_token_of_not_type_string(driver_config_client: TestClient):
    token = None

    async def custom_f(user, email_verification_url_token):
        nonlocal token
        token = email_verification_url_token.split(
            "?token=")[1].split("&ride")[0]

    init(
        supertokens_config=SupertokensConfig('http://localhost:3567'),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth"
        ),
        framework='fastapi',
        recipe_list=[session.init(
            anti_csrf='VIA_TOKEN'
        ), emailpassword.init(
            email_verification_feature=emailpassword.InputEmailVerificationConfig(
                create_and_send_custom_email=custom_f
            )
        )]
    )
    start_st()

    response_1 = sign_up_request(
        driver_config_client,
        "test@gmail.com",
        "testPass123")
    await asyncio.sleep(1)
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"
    user_id = dict_response["user"]["id"]

    cookies = extract_all_cookies(response_1)

    response_2 = email_verify_token_request(driver_config_client, cookies['sAccessToken']['value'],
                                            cookies['sIdRefreshToken']['value'], response_1.headers.get(
                                                'anti-csrf'),
                                            user_id)
    await asyncio.sleep(2)

    dict_response = json.loads(response_2.text)
    assert dict_response['status'] == 'OK'

    assert token is not None

    response_3 = driver_config_client.post(
        url="/auth/user/email/verify",
        headers={
            "Content-Type": "application/json",
            'anti-csrf': response_1.headers.get('anti-csrf')
        },
        cookies={
            'sRefreshToken': cookies['sRefreshToken']['value'],
            'sIdRefreshToken': cookies['sIdRefreshToken']['value'],
        },
        json={
            "method": "token",
            "token": 200
        }
    )

    dict_response = json.loads(response_3.text)
    assert response_3.status_code == 400
    assert dict_response['message'] == 'The email verification token must be a string'


@mark.asyncio
async def test_that_the_handle_post_email_verification_callback_is_called_on_successful_verification_if_given(
        driver_config_client: TestClient):
    token = None
    user_info_from_callback = None

    async def custom_f(user, email_verification_url_token):
        nonlocal token
        token = email_verification_url_token.split(
            "?token=")[1].split("&ride")[0]

    def apis_override_email_password(param: APIInterface):
        temp = param.email_verify_post

        async def email_verify_post(token: str, api_options: APIOptions):
            nonlocal user_info_from_callback

            response = await temp(token, api_options)

            if response.status == "OK":
                user_info_from_callback = response.user

            return response

        param.email_verify_post = email_verify_post
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
        recipe_list=[session.init(
            anti_csrf='VIA_TOKEN'
        ), emailpassword.init(
            email_verification_feature=emailpassword.InputEmailVerificationConfig(
                create_and_send_custom_email=custom_f
            ),
            override=emailpassword.InputOverrideConfig(
                email_verification_feature=OverrideConfig(
                    apis=apis_override_email_password
                )
            )
        )]
    )
    start_st()

    response_1 = sign_up_request(
        driver_config_client,
        "test@gmail.com",
        "testPass123")
    await asyncio.sleep(1)
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"
    user_id = dict_response["user"]["id"]

    cookies = extract_all_cookies(response_1)

    response_2 = email_verify_token_request(driver_config_client, cookies['sAccessToken']['value'],
                                            cookies['sIdRefreshToken']['value'], response_1.headers.get(
                                                'anti-csrf'),
                                            user_id)
    await asyncio.sleep(2)

    dict_response = json.loads(response_2.text)
    assert dict_response['status'] == 'OK'

    assert token is not None

    response_3 = driver_config_client.post(
        url="/auth/user/email/verify",
        headers={
            "Content-Type": "application/json",
            'anti-csrf': response_1.headers.get('anti-csrf')
        },
        cookies={
            'sRefreshToken': cookies['sRefreshToken']['value'],
            'sIdRefreshToken': cookies['sIdRefreshToken']['value'],
        },
        json={
            "method": "token",
            "token": token
        }
    )

    dict_response = json.loads(response_3.text)
    assert response_3.status_code == 200
    assert dict_response['status'] == 'OK'

    await asyncio.sleep(1)

    assert user_info_from_callback.user_id == user_id
    assert user_info_from_callback.email == "test@gmail.com"


@mark.asyncio
async def test_the_email_verify_with_valid_input_using_the_get_method(driver_config_client: TestClient):
    token = None

    async def custom_f(user, email_verification_url_token):
        nonlocal token
        token = email_verification_url_token.split(
            "?token=")[1].split("&ride")[0]

    init(
        supertokens_config=SupertokensConfig('http://localhost:3567'),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth"
        ),
        framework='fastapi',
        recipe_list=[session.init(
            anti_csrf='VIA_TOKEN'
        ), emailpassword.init(
            email_verification_feature=emailpassword.InputEmailVerificationConfig(
                create_and_send_custom_email=custom_f
            )
        )]
    )
    start_st()

    response_1 = sign_up_request(
        driver_config_client,
        "test@gmail.com",
        "testPass123")
    await asyncio.sleep(1)
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"
    user_id = dict_response["user"]["id"]

    cookies = extract_all_cookies(response_1)

    response_2 = email_verify_token_request(driver_config_client, cookies['sAccessToken']['value'],
                                            cookies['sIdRefreshToken']['value'], response_1.headers.get(
                                                'anti-csrf'),
                                            user_id)
    await asyncio.sleep(2)

    dict_response = json.loads(response_2.text)
    assert dict_response['status'] == 'OK'

    assert token is not None

    response_3 = driver_config_client.post(
        url="/auth/user/email/verify",
        json={
            "method": "token",
            "token": token
        }
    )

    dict_response = json.loads(response_3.text)
    assert response_3.status_code == 200
    assert dict_response['status'] == "OK"

    response_4 = driver_config_client.get(
        url="/auth/user/email/verify",
        headers={
            "Content-Type": "application/json",
            'anti-csrf': response_1.headers.get('anti-csrf')
        },
        cookies={
            'sAccessToken': cookies['sAccessToken']['value'],
            'sIdRefreshToken': cookies['sIdRefreshToken']['value'],
        })

    dict_response = json.loads(response_4.text)
    assert response_4.status_code == 200
    assert dict_response['status'] == 'OK'


@mark.asyncio
async def test_the_email_verify_with_no_session_using_the_get_method(driver_config_client: TestClient):
    init(
        supertokens_config=SupertokensConfig('http://localhost:3567'),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth"
        ),
        framework='fastapi',
        recipe_list=[session.init(
            anti_csrf='VIA_TOKEN'
        ), emailpassword.init()]
    )
    start_st()

    response_4 = driver_config_client.get(url="/auth/user/email/verify")

    dict_response = json.loads(response_4.text)
    assert response_4.status_code == 401
    assert dict_response['message'] == 'unauthorised'


@mark.asyncio
async def test_the_email_verify_api_with_valid_input_overriding_apis(driver_config_client: TestClient):
    token = None
    user_info_from_callback = None

    async def custom_f(user, email_verification_url_token):
        nonlocal token
        token = email_verification_url_token.split(
            "?token=")[1].split("&ride")[0]

    def apis_override_email_password(param: APIInterface):
        temp = param.email_verify_post

        async def email_verify_post(token: str, api_options: APIOptions):
            nonlocal user_info_from_callback

            response = await temp(token, api_options)

            if response.status == "OK":
                user_info_from_callback = response.user

            return response

        param.email_verify_post = email_verify_post
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
        recipe_list=[session.init(
            anti_csrf='VIA_TOKEN'
        ), emailpassword.init(
            email_verification_feature=emailpassword.InputEmailVerificationConfig(
                create_and_send_custom_email=custom_f
            ),
            override=emailpassword.InputOverrideConfig(
                email_verification_feature=OverrideConfig(
                    apis=apis_override_email_password
                )
            )
        )]
    )
    start_st()

    response_1 = sign_up_request(
        driver_config_client,
        "test@gmail.com",
        "testPass123")
    await asyncio.sleep(1)
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"
    user_id = dict_response["user"]["id"]

    cookies = extract_all_cookies(response_1)

    response_2 = email_verify_token_request(driver_config_client, cookies['sAccessToken']['value'],
                                            cookies['sIdRefreshToken']['value'], response_1.headers.get(
                                                'anti-csrf'),
                                            user_id)
    await asyncio.sleep(2)

    dict_response = json.loads(response_2.text)
    assert dict_response['status'] == 'OK'

    assert token is not None

    response_3 = driver_config_client.post(
        url="/auth/user/email/verify",
        json={
            "method": "token",
            "token": token
        }
    )

    dict_response = json.loads(response_3.text)
    assert response_3.status_code == 200
    assert dict_response['status'] == 'OK'

    await asyncio.sleep(1)

    assert user_info_from_callback.user_id == user_id
    assert user_info_from_callback.email == "test@gmail.com"


@mark.asyncio
async def test_the_email_verify_api_with_valid_input_overriding_apis_throws_error(driver_config_client: TestClient):
    token = None
    user_info_from_callback = None

    async def custom_f(user, email_verification_url_token):
        nonlocal token
        token = email_verification_url_token.split(
            "?token=")[1].split("&ride")[0]

    def apis_override_email_password(param: APIInterface):
        temp = param.email_verify_post

        async def email_verify_post(token: str, api_options: APIOptions):
            nonlocal user_info_from_callback

            response = await temp(token, api_options)

            if response.status == "OK":
                user_info_from_callback = response.user

            raise BadInputError("verify exception")

        param.email_verify_post = email_verify_post
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
        recipe_list=[session.init(
            anti_csrf='VIA_TOKEN'
        ), emailpassword.init(
            email_verification_feature=emailpassword.InputEmailVerificationConfig(
                create_and_send_custom_email=custom_f
            ),
            override=emailpassword.InputOverrideConfig(
                email_verification_feature=OverrideConfig(
                    apis=apis_override_email_password
                )
            )
        )]
    )
    start_st()

    response_1 = sign_up_request(
        driver_config_client,
        "test@gmail.com",
        "testPass123")
    await asyncio.sleep(1)
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"
    user_id = dict_response["user"]["id"]

    cookies = extract_all_cookies(response_1)

    response_2 = email_verify_token_request(driver_config_client, cookies['sAccessToken']['value'],
                                            cookies['sIdRefreshToken']['value'], response_1.headers.get(
                                                'anti-csrf'),
                                            user_id)
    await asyncio.sleep(2)

    dict_response = json.loads(response_2.text)
    assert dict_response['status'] == 'OK'

    assert token is not None

    response_3 = driver_config_client.post(
        url="/auth/user/email/verify",
        json={
            "method": "token",
            "token": token
        }
    )

    dict_response = json.loads(response_3.text)
    assert response_3.status_code == 400
    assert dict_response['message'] == 'verify exception'

    await asyncio.sleep(1)

    assert user_info_from_callback.user_id == user_id
    assert user_info_from_callback.email == "test@gmail.com"


@mark.asyncio
async def test_the_generate_token_api_with_valid_input_and_then_remove_token(driver_config_client: TestClient):
    init(
        supertokens_config=SupertokensConfig('http://localhost:3567'),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth"
        ),
        framework='fastapi',
        recipe_list=[session.init(
            anti_csrf='VIA_TOKEN'
        ), emailpassword.init()]
    )
    start_st()

    version = await Querier.get_instance().get_api_version()
    assert version == "2.9"

    response_1 = sign_up_request(
        driver_config_client,
        "test@gmail.com",
        "testPass123")
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"
    user_id = dict_response["user"]["id"]

    verify_token = await create_email_verification_token(user_id)
    await revoke_email_verification_token(user_id)

    response = await verify_email_using_token(verify_token.token)
    assert response.status == "EMAIL_VERIFICATION_INVALID_TOKEN_ERROR"


@mark.asyncio
async def test_the_generate_token_api_with_valid_input_verify_and_then_unverify_email(driver_config_client: TestClient):
    init(
        supertokens_config=SupertokensConfig('http://localhost:3567'),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth"
        ),
        framework='fastapi',
        recipe_list=[session.init(
            anti_csrf='VIA_TOKEN'
        ), emailpassword.init()]
    )
    start_st()

    version = await Querier.get_instance().get_api_version()
    assert version == "2.9"

    response_1 = sign_up_request(
        driver_config_client,
        "test@gmail.com",
        "testPass123")
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"
    user_id = dict_response["user"]["id"]

    verify_token = await create_email_verification_token(user_id)
    await verify_email_using_token(verify_token.token)

    assert (await is_email_verified(user_id))

    await unverify_email(user_id)

    is_verified = await is_email_verified(user_id)
    assert is_verified is False
