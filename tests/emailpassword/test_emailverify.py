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
from typing import Any, Dict, Union, Optional

from fastapi import FastAPI
from fastapi.requests import Request
from fastapi.testclient import TestClient
from pytest import fixture, mark, skip
from supertokens_python import InputAppInfo, SupertokensConfig, init
from supertokens_python.asyncio import delete_user
from supertokens_python.exceptions import BadInputError
from supertokens_python.framework.fastapi import get_middleware
from supertokens_python.querier import Querier
from supertokens_python.recipe import emailpassword, session, emailverification
from supertokens_python.recipe.emailverification.asyncio import (
    create_email_verification_token,
    is_email_verified,
    revoke_email_verification_tokens,
    unverify_email,
    verify_email_using_token,
)
from supertokens_python.recipe.emailverification.interfaces import (
    APIInterface,
    APIOptions,
    CreateEmailVerificationTokenOkResult,
    EmailVerifyPostOkResult,
    VerifyEmailUsingTokenInvalidTokenError,
)
from supertokens_python.recipe.emailverification.types import User as EVUser
from supertokens_python.recipe.emailverification.utils import (
    OverrideConfig,
)
from supertokens_python.recipe.session import SessionContainer
from supertokens_python.recipe.session.asyncio import (
    create_new_session,
    get_session,
    refresh_session,
)
from supertokens_python.recipe.session.constants import ANTI_CSRF_HEADER_KEY
from supertokens_python.utils import is_version_gte
from tests.utils import get_st_init_args, min_api_version
from tests.utils import (
    TEST_ACCESS_TOKEN_MAX_AGE_CONFIG_KEY,
    email_verify_token_request,
    extract_all_cookies,
    set_key_value_in_config,
    sign_up_request,
    start_st,
    setup_function,
    teardown_function,
)

_ = setup_function  # type: ignore
_ = teardown_function  # type: ignore

pytestmark = mark.asyncio


@fixture(scope="function")
async def driver_config_client():
    app = FastAPI()
    app.add_middleware(get_middleware())

    @app.get("/login")
    async def login(request: Request):  # type: ignore
        user_id = "userId"
        await create_new_session(request, user_id, {}, {})
        return {"userId": user_id}

    @app.post("/refresh")
    async def custom_refresh(request: Request):  # type: ignore
        await refresh_session(request)
        return {}  # type: ignore

    @app.get("/info")
    async def info_get(request: Request):  # type: ignore
        await get_session(request, True)
        return {}  # type: ignore

    @app.get("/custom/info")
    def custom_info(_):  # type: ignore
        return {}  # type: ignore

    @app.options("/custom/handle")
    def custom_handle_options(_):  # type: ignore
        return {"method": "option"}

    @app.get("/handle")
    async def handle_get(request: Request):  # type: ignore
        session: Union[SessionContainer, None] = await get_session(request, True)
        if session is None:
            raise Exception("Should never come here")
        return {"s": session.get_handle()}

    @app.post("/logout")
    async def custom_logout(request: Request):  # type: ignore
        session: Union[SessionContainer, None] = await get_session(request, True)
        if session is None:
            raise Exception("Should never come here")
        await session.revoke_session()
        return {}  # type: ignore

    return TestClient(app)


async def test_the_generate_token_api_with_valid_input_email_not_verified(
    driver_config_client: TestClient,
):
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
            session.init(anti_csrf="VIA_TOKEN"),
            emailverification.init("OPTIONAL"),
            emailpassword.init(),
        ],
    )
    start_st()

    response_1 = sign_up_request(driver_config_client, "test@gmail.com", "testPass123")

    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"

    user_id = dict_response["user"]["id"]
    cookies = extract_all_cookies(response_1)

    response = email_verify_token_request(
        driver_config_client,
        cookies["sAccessToken"]["value"],
        cookies["sIdRefreshToken"]["value"],
        response_1.headers.get("anti-csrf"),  # type: ignore
        user_id,
    )
    dict_response = json.loads(response.text)
    assert dict_response["status"] == "OK"


async def test_the_generate_token_api_with_valid_input_email_verified_and_test_error(
    driver_config_client: TestClient,
):
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
            session.init(anti_csrf="VIA_TOKEN"),
            emailverification.init("OPTIONAL"),
            emailpassword.init(),
        ],
    )
    start_st()

    response_1 = sign_up_request(driver_config_client, "test@gmail.com", "testPass123")

    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"

    user_id = dict_response["user"]["id"]
    cookies = extract_all_cookies(response_1)

    verify_token = await create_email_verification_token(user_id)
    if isinstance(verify_token, CreateEmailVerificationTokenOkResult):
        await verify_email_using_token(verify_token.token)

        response = email_verify_token_request(
            driver_config_client,
            cookies["sAccessToken"]["value"],
            cookies["sIdRefreshToken"]["value"],
            response_1.headers.get("anti-csrf"),  # type: ignore
            user_id,
        )
        dict_response = json.loads(response.text)
        assert dict_response["status"] == "EMAIL_ALREADY_VERIFIED_ERROR"
        return
    raise Exception("Test failed")


async def test_the_generate_token_api_with_valid_input_no_session_and_check_output(
    driver_config_client: TestClient,
):
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
            session.init(anti_csrf="VIA_TOKEN"),
            emailverification.init("OPTIONAL"),
            emailpassword.init(),
        ],
    )
    start_st()

    response_1 = driver_config_client.post(url="/auth/user/email/verify/token")
    assert response_1.status_code == 401
    dict_response = json.loads(response_1.text)
    assert dict_response["message"] == "unauthorised"


async def test_the_generate_token_api_with_an_expired_access_token_and_see_that_try_refresh_token_is_returned(
    driver_config_client: TestClient,
):
    set_key_value_in_config(TEST_ACCESS_TOKEN_MAX_AGE_CONFIG_KEY, "2")

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
            session.init(anti_csrf="VIA_TOKEN"),
            emailverification.init("OPTIONAL"),
            emailpassword.init(),
        ],
    )
    start_st()

    response_1 = sign_up_request(driver_config_client, "test@gmail.com", "testPass123")
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"
    user_id = dict_response["user"]["id"]

    cookies = extract_all_cookies(response_1)

    await asyncio.sleep(5)

    response_2 = email_verify_token_request(
        driver_config_client,
        cookies["sAccessToken"]["value"],
        cookies["sIdRefreshToken"]["value"],
        response_1.headers.get("anti-csrf"),  # type: ignore
        user_id,
    )
    dict_response = json.loads(response_2.text)

    assert response_2.status_code == 401
    assert dict_response["message"] == "try refresh token"

    response_3 = driver_config_client.post(
        url="/auth/session/refresh",
        headers={
            "Content-Type": "application/json",
            "anti-csrf": response_1.headers.get("anti-csrf"),
        },
        cookies={
            "sRefreshToken": cookies["sRefreshToken"]["value"],
            "sIdRefreshToken": cookies["sIdRefreshToken"]["value"],
        },
    )

    assert response_3.status_code == 200

    cookies1 = extract_all_cookies(response_3)
    response_4 = email_verify_token_request(
        driver_config_client,
        cookies1["sAccessToken"]["value"],
        cookies1["sIdRefreshToken"]["value"],
        response_3.headers.get("anti-csrf"),  # type: ignore
        user_id,
    )

    dict_response = json.loads(response_4.text)

    assert response_4.status_code == 200
    assert dict_response["status"] == "OK"


async def test_that_providing_your_own_email_callback_and_make_sure_it_is_called(
    driver_config_client: TestClient,
):
    user_info: Union[None, EVUser] = None
    email_token = None

    async def custom_f(
        user: EVUser, email_verification_url_token: str, _: Dict[str, Any]
    ):
        nonlocal user_info, email_token
        user_info = user
        email_token = email_verification_url_token

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
            session.init(anti_csrf="VIA_TOKEN"),
            emailverification.init(
                mode="REQUIRED", create_and_send_custom_email=custom_f
            ),
            emailpassword.init(),
        ],
    )
    start_st()

    response_1 = sign_up_request(driver_config_client, "test@gmail.com", "testPass123")
    await asyncio.sleep(1)
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"
    user_id: str = dict_response["user"]["id"]

    cookies = extract_all_cookies(response_1)

    response_2 = email_verify_token_request(
        driver_config_client,
        cookies["sAccessToken"]["value"],
        cookies["sIdRefreshToken"]["value"],
        response_1.headers.get("anti-csrf"),  # type: ignore
        user_id,
    )
    await asyncio.sleep(2)

    dict_response = json.loads(response_2.text)
    assert dict_response["status"] == "OK"
    if user_info is None:
        raise Exception("Should never come here")
    assert user_info.user_id == user_id  # type: ignore
    assert user_info.email == "test@gmail.com"  # type: ignore
    assert email_token is not None


async def test_the_email_verify_api_with_valid_input(driver_config_client: TestClient):
    token = None

    async def custom_f(
        _: EVUser, email_verification_url_token: str, __: Dict[str, Any]
    ):
        nonlocal token
        token = email_verification_url_token.split("?token=")[1].split("&rid=")[0]

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
            session.init(anti_csrf="VIA_TOKEN"),
            emailverification.init(
                mode="REQUIRED", create_and_send_custom_email=custom_f
            ),
            emailpassword.init(),
        ],
    )
    start_st()

    response_1 = sign_up_request(driver_config_client, "test@gmail.com", "testPass123")
    await asyncio.sleep(1)
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"
    user_id = dict_response["user"]["id"]

    cookies = extract_all_cookies(response_1)

    response_2 = email_verify_token_request(
        driver_config_client,
        cookies["sAccessToken"]["value"],
        cookies["sIdRefreshToken"]["value"],
        response_1.headers.get("anti-csrf"),  # type: ignore
        user_id,
    )
    await asyncio.sleep(2)

    dict_response = json.loads(response_2.text)
    assert dict_response["status"] == "OK"

    assert token is not None

    response_3 = driver_config_client.post(
        url="/auth/user/email/verify",
        headers={
            "Content-Type": "application/json",
            "anti-csrf": response_1.headers.get("anti-csrf"),
        },
        cookies={
            "sRefreshToken": cookies["sRefreshToken"]["value"],
            "sIdRefreshToken": cookies["sIdRefreshToken"]["value"],
        },
        json={"method": "token", "token": token},
    )

    dict_response = json.loads(response_3.text)
    assert dict_response["status"] == "OK"


async def test_the_email_verify_api_with_invalid_token_and_check_error(
    driver_config_client: TestClient,
):
    token = None

    async def custom_f(
        _: EVUser, email_verification_url_token: str, __: Dict[str, Any]
    ):
        nonlocal token
        token = email_verification_url_token.split("?token=")[1].split("&rid=")[0]

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
            session.init(anti_csrf="VIA_TOKEN"),
            emailverification.init(
                mode="REQUIRED", create_and_send_custom_email=custom_f
            ),
            emailpassword.init(),
        ],
    )
    start_st()

    response_1 = sign_up_request(driver_config_client, "test@gmail.com", "testPass123")
    await asyncio.sleep(1)
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"
    user_id = dict_response["user"]["id"]

    cookies = extract_all_cookies(response_1)

    response_2 = email_verify_token_request(
        driver_config_client,
        cookies["sAccessToken"]["value"],
        cookies["sIdRefreshToken"]["value"],
        response_1.headers.get("anti-csrf"),  # type: ignore
        user_id,
    )
    await asyncio.sleep(2)

    dict_response = json.loads(response_2.text)
    assert dict_response["status"] == "OK"

    assert token is not None

    response_3 = driver_config_client.post(
        url="/auth/user/email/verify",
        headers={
            "Content-Type": "application/json",
            "anti-csrf": response_1.headers.get("anti-csrf"),
        },
        cookies={
            "sRefreshToken": cookies["sRefreshToken"]["value"],
            "sIdRefreshToken": cookies["sIdRefreshToken"]["value"],
        },
        json={"method": "token", "token": "bad token"},
    )

    dict_response = json.loads(response_3.text)
    assert dict_response["status"] == "EMAIL_VERIFICATION_INVALID_TOKEN_ERROR"


async def test_the_email_verify_api_with_token_of_not_type_string(
    driver_config_client: TestClient,
):
    token = None

    async def custom_f(
        _: EVUser, email_verification_url_token: str, __: Dict[str, Any]
    ):
        nonlocal token
        token = email_verification_url_token.split("?token=")[1].split("&rid=")[0]

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
            session.init(anti_csrf="VIA_TOKEN"),
            emailverification.init(
                mode="REQUIRED", create_and_send_custom_email=custom_f
            ),
            emailpassword.init(),
        ],
    )
    start_st()

    response_1 = sign_up_request(driver_config_client, "test@gmail.com", "testPass123")
    await asyncio.sleep(1)
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"
    user_id = dict_response["user"]["id"]

    cookies = extract_all_cookies(response_1)

    response_2 = email_verify_token_request(
        driver_config_client,
        cookies["sAccessToken"]["value"],
        cookies["sIdRefreshToken"]["value"],
        response_1.headers.get("anti-csrf"),  # type: ignore
        user_id,
    )
    await asyncio.sleep(2)

    dict_response = json.loads(response_2.text)
    assert dict_response["status"] == "OK"

    assert token is not None

    response_3 = driver_config_client.post(
        url="/auth/user/email/verify",
        headers={
            "Content-Type": "application/json",
            "anti-csrf": response_1.headers.get("anti-csrf"),
        },
        cookies={
            "sRefreshToken": cookies["sRefreshToken"]["value"],
            "sIdRefreshToken": cookies["sIdRefreshToken"]["value"],
        },
        json={"method": "token", "token": 200},
    )

    dict_response = json.loads(response_3.text)
    assert response_3.status_code == 400
    assert dict_response["message"] == "The email verification token must be a string"


async def test_that_the_handle_post_email_verification_callback_is_called_on_successful_verification_if_given(
    driver_config_client: TestClient,
):
    token = None
    user_info_from_callback: Union[None, EVUser] = None

    async def custom_f(
        _: EVUser, email_verification_url_token: str, __: Dict[str, Any]
    ):
        nonlocal token
        token = email_verification_url_token.split("?token=")[1].split("&rid=")[0]

    def apis_override_email_password(param: APIInterface):
        temp = param.email_verify_post

        async def email_verify_post(
            token: str,
            session: Optional[SessionContainer],
            api_options: APIOptions,
            user_context: Dict[str, Any],
        ):
            nonlocal user_info_from_callback

            response = await temp(token, session, api_options, user_context)

            if isinstance(response, EmailVerifyPostOkResult):
                user_info_from_callback = response.user

            return response

        param.email_verify_post = email_verify_post
        return param

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
            session.init(anti_csrf="VIA_TOKEN"),
            emailverification.init(
                mode="REQUIRED",
                create_and_send_custom_email=custom_f,
                override=OverrideConfig(apis=apis_override_email_password),
            ),
            emailpassword.init(),
        ],
    )
    start_st()

    response_1 = sign_up_request(driver_config_client, "test@gmail.com", "testPass123")
    await asyncio.sleep(1)
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"
    user_id = dict_response["user"]["id"]

    cookies = extract_all_cookies(response_1)

    response_2 = email_verify_token_request(
        driver_config_client,
        cookies["sAccessToken"]["value"],
        cookies["sIdRefreshToken"]["value"],
        response_1.headers.get("anti-csrf"),  # type: ignore
        user_id,
    )
    await asyncio.sleep(2)

    dict_response = json.loads(response_2.text)
    assert dict_response["status"] == "OK"

    assert token is not None

    response_3 = driver_config_client.post(
        url="/auth/user/email/verify",
        headers={
            "Content-Type": "application/json",
            "anti-csrf": response_1.headers.get("anti-csrf"),
        },
        cookies={
            "sRefreshToken": cookies["sRefreshToken"]["value"],
            "sIdRefreshToken": cookies["sIdRefreshToken"]["value"],
        },
        json={"method": "token", "token": token},
    )

    dict_response = json.loads(response_3.text)
    assert response_3.status_code == 200
    assert dict_response["status"] == "OK"

    await asyncio.sleep(1)
    if user_info_from_callback is None:
        raise Exception("Should never come here")
    assert user_info_from_callback.user_id == user_id  # type: ignore
    assert user_info_from_callback.email == "test@gmail.com"  # type: ignore


async def test_the_email_verify_with_valid_input_using_the_get_method(
    driver_config_client: TestClient,
):
    token = None

    async def custom_f(
        _: EVUser, email_verification_url_token: str, __: Dict[str, Any]
    ):
        nonlocal token
        token = email_verification_url_token.split("?token=")[1].split("&rid=")[0]

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
            session.init(anti_csrf="VIA_TOKEN"),
            emailverification.init(
                mode="REQUIRED",
                create_and_send_custom_email=custom_f,
            ),
            emailpassword.init(),
        ],
    )
    start_st()

    response_1 = sign_up_request(driver_config_client, "test@gmail.com", "testPass123")
    await asyncio.sleep(1)
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"
    user_id = dict_response["user"]["id"]

    cookies = extract_all_cookies(response_1)

    response_2 = email_verify_token_request(
        driver_config_client,
        cookies["sAccessToken"]["value"],
        cookies["sIdRefreshToken"]["value"],
        response_1.headers.get("anti-csrf"),  # type: ignore
        user_id,
    )
    await asyncio.sleep(2)

    dict_response = json.loads(response_2.text)
    assert dict_response["status"] == "OK"

    assert token is not None

    response_3 = driver_config_client.post(
        url="/auth/user/email/verify",
        json={"method": "token", "token": token},
        headers={ANTI_CSRF_HEADER_KEY: response_1.headers.get("anti-csrf")},
    )

    dict_response = json.loads(response_3.text)
    assert response_3.status_code == 200
    assert dict_response["status"] == "OK"

    response_4 = driver_config_client.get(
        url="/auth/user/email/verify",
        headers={
            "Content-Type": "application/json",
            "anti-csrf": response_1.headers.get("anti-csrf"),
        },
        cookies={
            "sAccessToken": cookies["sAccessToken"]["value"],
            "sIdRefreshToken": cookies["sIdRefreshToken"]["value"],
        },
    )

    dict_response = json.loads(response_4.text)
    assert response_4.status_code == 200
    assert dict_response["status"] == "OK"


async def test_the_email_verify_with_no_session_using_the_get_method(
    driver_config_client: TestClient,
):
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
            session.init(anti_csrf="VIA_TOKEN"),
            emailverification.init("OPTIONAL"),
            emailpassword.init(),
        ],
    )
    start_st()

    response_4 = driver_config_client.get(url="/auth/user/email/verify")

    dict_response = json.loads(response_4.text)
    assert response_4.status_code == 401
    assert dict_response["message"] == "unauthorised"


async def test_the_email_verify_api_with_valid_input_overriding_apis(
    driver_config_client: TestClient,
):
    token = None
    user_info_from_callback: Union[None, EVUser] = None

    async def custom_f(
        _: EVUser, email_verification_url_token: str, __: Dict[str, Any]
    ):
        nonlocal token
        token = email_verification_url_token.split("?token=")[1].split("&rid=")[0]

    def apis_override_email_password(param: APIInterface):
        temp = param.email_verify_post

        async def email_verify_post(
            token: str,
            session: Optional[SessionContainer],
            api_options: APIOptions,
            user_context: Dict[str, Any],
        ):
            nonlocal user_info_from_callback

            response = await temp(token, session, api_options, user_context)

            if isinstance(response, EmailVerifyPostOkResult):
                user_info_from_callback = response.user

            return response

        param.email_verify_post = email_verify_post
        return param

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
            session.init(anti_csrf="VIA_TOKEN"),
            emailverification.init(
                mode="REQUIRED",
                create_and_send_custom_email=custom_f,
                override=OverrideConfig(apis=apis_override_email_password),
            ),
            emailpassword.init(),
        ],
    )
    start_st()

    response_1 = sign_up_request(driver_config_client, "test@gmail.com", "testPass123")
    await asyncio.sleep(1)
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"
    user_id = dict_response["user"]["id"]

    cookies = extract_all_cookies(response_1)

    response_2 = email_verify_token_request(
        driver_config_client,
        cookies["sAccessToken"]["value"],
        cookies["sIdRefreshToken"]["value"],
        response_1.headers.get("anti-csrf"),  # type: ignore
        user_id,
    )
    await asyncio.sleep(2)

    dict_response = json.loads(response_2.text)
    assert dict_response["status"] == "OK"

    assert token is not None

    response_3 = driver_config_client.post(
        url="/auth/user/email/verify",
        json={"method": "token", "token": token},
        headers={ANTI_CSRF_HEADER_KEY: response_1.headers.get("anti-csrf")},
    )

    dict_response = json.loads(response_3.text)
    assert response_3.status_code == 200
    assert dict_response["status"] == "OK"

    await asyncio.sleep(1)

    if user_info_from_callback is None:
        raise Exception("Should never come here")
    assert user_info_from_callback.user_id == user_id  # type: ignore
    assert user_info_from_callback.email == "test@gmail.com"  # type: ignore


async def test_the_email_verify_api_with_valid_input_overriding_apis_throws_error(
    driver_config_client: TestClient,
):
    token = None
    user_info_from_callback: Union[None, EVUser] = None

    async def custom_f(
        _: EVUser, email_verification_url_token: str, __: Dict[str, Any]
    ):
        nonlocal token
        token = email_verification_url_token.split("?token=")[1].split("&rid=")[0]

    def apis_override_email_password(param: APIInterface):
        temp = param.email_verify_post

        async def email_verify_post(
            token: str,
            session: Optional[SessionContainer],
            api_options: APIOptions,
            user_context: Dict[str, Any],
        ):
            nonlocal user_info_from_callback

            response = await temp(token, session, api_options, user_context)

            if isinstance(response, EmailVerifyPostOkResult):
                user_info_from_callback = response.user

            raise BadInputError("verify exception")

        param.email_verify_post = email_verify_post
        return param

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
            session.init(anti_csrf="VIA_TOKEN"),
            emailverification.init(
                mode="REQUIRED",
                create_and_send_custom_email=custom_f,
                override=emailverification.InputOverrideConfig(
                    apis=apis_override_email_password
                ),
            ),
            emailpassword.init(),
        ],
    )
    start_st()

    response_1 = sign_up_request(driver_config_client, "test@gmail.com", "testPass123")
    await asyncio.sleep(1)
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"
    user_id = dict_response["user"]["id"]

    cookies = extract_all_cookies(response_1)

    response_2 = email_verify_token_request(
        driver_config_client,
        cookies["sAccessToken"]["value"],
        cookies["sIdRefreshToken"]["value"],
        response_1.headers.get("anti-csrf"),  # type: ignore
        user_id,
    )
    await asyncio.sleep(2)

    dict_response = json.loads(response_2.text)
    assert dict_response["status"] == "OK"

    assert token is not None

    response_3 = driver_config_client.post(
        url="/auth/user/email/verify",
        json={"method": "token", "token": token},
        headers={ANTI_CSRF_HEADER_KEY: response_1.headers.get("anti-csrf")},
    )

    dict_response = json.loads(response_3.text)
    assert response_3.status_code == 400
    assert dict_response["message"] == "verify exception"

    await asyncio.sleep(1)

    if user_info_from_callback is None:
        raise Exception("Should never come here")
    assert user_info_from_callback.user_id == user_id  # type: ignore
    assert user_info_from_callback.email == "test@gmail.com"  # type: ignore


async def test_the_generate_token_api_with_valid_input_and_then_remove_token(
    driver_config_client: TestClient,
):
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
            session.init(anti_csrf="VIA_TOKEN"),
            emailverification.init("OPTIONAL"),
            emailpassword.init(),
        ],
    )
    start_st()

    version = await Querier.get_instance().get_api_version()
    if not is_version_gte(version, "2.9"):
        # If the version less than 2.9, the recipe doesn't exist. So skip the test
        skip()

    response_1 = sign_up_request(driver_config_client, "test@gmail.com", "testPass123")
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"
    user_id = dict_response["user"]["id"]

    verify_token = await create_email_verification_token(user_id)
    await revoke_email_verification_tokens(user_id)

    if isinstance(verify_token, CreateEmailVerificationTokenOkResult):
        response = await verify_email_using_token(verify_token.token)
        assert isinstance(response, VerifyEmailUsingTokenInvalidTokenError)
        return
    raise Exception("Test failed")


async def test_the_generate_token_api_with_valid_input_verify_and_then_unverify_email(
    driver_config_client: TestClient,
):
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
            session.init(anti_csrf="VIA_TOKEN"),
            emailverification.init(mode="OPTIONAL"),
            emailpassword.init(),
        ],
    )
    start_st()

    version = await Querier.get_instance().get_api_version()
    if not is_version_gte(version, "2.9"):
        # If the version is less than 2.9, the recipe doesn't exist. So skip the test.
        skip()

    response_1 = sign_up_request(driver_config_client, "test@gmail.com", "testPass123")
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"
    user_id = dict_response["user"]["id"]

    verify_token = await create_email_verification_token(user_id)
    if isinstance(verify_token, CreateEmailVerificationTokenOkResult):
        await verify_email_using_token(verify_token.token)

        assert await is_email_verified(user_id)

        await unverify_email(user_id)

        is_verified = await is_email_verified(user_id)
        assert is_verified is False
        return
    raise Exception("Test failed")


@min_api_version("2.11")
async def test_email_verify_with_deleted_user(driver_config_client: TestClient):
    async def custom_f(_: EVUser, __: str, ___: Optional[Dict[str, Any]]):
        return None

    st_args = get_st_init_args(
        [
            emailpassword.init(),
            emailverification.init("OPTIONAL", create_and_send_custom_email=custom_f),
            session.init(),
        ]
    )
    init(**st_args)
    start_st()

    res = sign_up_request(driver_config_client, "test@gmail.com", "testPass123")
    dict_response = json.loads(res.text)

    assert res.status_code == 200
    assert dict_response["status"] == "OK"

    user_id = dict_response["user"]["id"]
    cookies = extract_all_cookies(res)

    await delete_user(user_id)

    response = email_verify_token_request(
        driver_config_client,
        cookies["sAccessToken"]["value"],
        cookies["sIdRefreshToken"]["value"],
        res.headers.get("anti-csrf"),  # type: ignore
        user_id,
    )
    dict_response = json.loads(response.text)

    assert response.status_code == 401
    assert dict_response == {"message": "unauthorised"}
