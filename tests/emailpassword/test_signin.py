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
from typing import Union

from fastapi import FastAPI
from fastapi.requests import Request
from pytest import fixture, mark
from supertokens_python import InputAppInfo, SupertokensConfig, init
from supertokens_python.asyncio import delete_user, get_user_count
from supertokens_python.framework.fastapi import get_middleware
from supertokens_python.querier import Querier
from supertokens_python.recipe import emailpassword, session
from supertokens_python.recipe.emailpassword.interfaces import APIInterface
from supertokens_python.recipe.session import SessionContainer
from supertokens_python.recipe.session.asyncio import (
    create_new_session,
    get_session,
    refresh_session,
)
from supertokens_python.types import RecipeUserId
from supertokens_python.utils import is_version_gte

from tests.testclient import TestClientWithNoCookieJar as TestClient
from tests.utils import extract_all_cookies, get_new_core_app_url, sign_up_request


@fixture(scope="function")
def driver_config_client():
    app = FastAPI()
    app.add_middleware(get_middleware())

    @app.get("/login")
    async def login(request: Request):  # type: ignore
        user_id = "userId"
        await create_new_session(request, "public", RecipeUserId(user_id), {}, {})
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
        session: Union[None, SessionContainer] = await get_session(request, True)
        if session is None:
            raise Exception("Should never come here")
        return {"s": session.get_handle()}

    @app.post("/logout")
    async def custom_logout(request: Request):  # type: ignore
        session: Union[None, SessionContainer] = await get_session(request, True)
        if session is None:
            raise Exception("Should never come here")
        await session.revoke_session()
        return {}  # type: ignore

    return TestClient(app)


@mark.asyncio
async def test_that_disabling_api_the_default_signin_API_does_not_work(
    driver_config_client: TestClient,
):
    def apis_override_email_password(param: APIInterface):
        param.disable_sign_in_post = True
        return param

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
            emailpassword.init(
                override=emailpassword.InputOverrideConfig(
                    apis=apis_override_email_password
                )
            )
        ],
    )

    response_1 = driver_config_client.post(
        url="/auth/signin",
        json={
            "formFields": [
                {"id": "password", "value": "validpass123"},
                {"id": "email", "value": "random@gmail.com"},
            ]
        },
    )

    assert response_1.status_code == 404


@mark.asyncio
async def test_singinAPI_works_when_input_is_fine(driver_config_client: TestClient):
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
            emailpassword.init(),
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
        ],
    )

    response_1 = sign_up_request(
        driver_config_client, "random@gmail.com", "validpass123"
    )
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    user_info = dict_response["user"]
    assert dict_response["status"] == "OK"

    response_2 = driver_config_client.post(
        url="/auth/signin",
        json={
            "formFields": [
                {"id": "password", "value": "validpass123"},
                {"id": "email", "value": "random@gmail.com"},
            ]
        },
    )

    assert response_2.status_code == 200
    dict_response = json.loads(response_2.text)
    assert dict_response["user"]["id"] == user_info["id"]
    assert dict_response["user"]["emails"] == user_info["emails"]


@mark.asyncio
async def test_singinAPI_works_when_input_is_fine_when_rid_is_tpep(
    driver_config_client: TestClient,
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
            emailpassword.init(),
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
        ],
    )

    response_1 = sign_up_request(
        driver_config_client, "random@gmail.com", "validpass123"
    )
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    user_info = dict_response["user"]
    assert dict_response["status"] == "OK"

    response_2 = driver_config_client.post(
        url="/auth/signin",
        headers={"rid": "thirdpartyemailpassword"},
        json={
            "formFields": [
                {"id": "password", "value": "validpass123"},
                {"id": "email", "value": "random@gmail.com"},
            ]
        },
    )

    assert response_2.status_code == 200
    dict_response = json.loads(response_2.text)
    assert dict_response["user"]["id"] == user_info["id"]
    assert dict_response["user"]["emails"] == user_info["emails"]


@mark.asyncio
async def test_singinAPI_works_when_input_is_fine_when_rid_is_emailpassword(
    driver_config_client: TestClient,
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
            emailpassword.init(),
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
        ],
    )

    response_1 = sign_up_request(
        driver_config_client, "random@gmail.com", "validpass123"
    )
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    user_info = dict_response["user"]
    assert dict_response["status"] == "OK"

    response_2 = driver_config_client.post(
        url="/auth/signin",
        headers={"rid": "emailpassword"},
        json={
            "formFields": [
                {"id": "password", "value": "validpass123"},
                {"id": "email", "value": "random@gmail.com"},
            ]
        },
    )

    assert response_2.status_code == 200
    dict_response = json.loads(response_2.text)
    assert dict_response["user"]["id"] == user_info["id"]
    assert dict_response["user"]["emails"] == user_info["emails"]


@mark.asyncio
async def test_singinAPI_throws_an_error_when_email_does_not_match(
    driver_config_client: TestClient,
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
            emailpassword.init(),
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
        ],
    )

    response_1 = sign_up_request(
        driver_config_client, "random@gmail.com", "validpass123"
    )
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"

    response_2 = driver_config_client.post(
        url="/auth/signin",
        json={
            "formFields": [
                {"id": "password", "value": "validpass123"},
                {"id": "email", "value": "ra@gmail.com"},
            ]
        },
    )

    assert response_2.status_code == 200
    dict_response = json.loads(response_2.text)
    assert dict_response["status"] == "WRONG_CREDENTIALS_ERROR"


@mark.asyncio
async def test_singin_api_throws_an_error_when_email_does_not_match(
    driver_config_client: TestClient,
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
            emailpassword.init(),
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
        ],
    )

    response_1 = sign_up_request(
        driver_config_client, "random@gmail.com", "validpass123"
    )
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"

    response_2 = driver_config_client.post(
        url="/auth/signin",
        json={
            "formFields": [
                {"id": "password", "value": "validpass123"},
                {"id": "email", "value": "ra@gmail.com"},
            ]
        },
    )

    assert response_2.status_code == 200
    dict_response = json.loads(response_2.text)
    assert dict_response["status"] == "WRONG_CREDENTIALS_ERROR"


@mark.asyncio
async def test_singinAPI_throws_an_error_if_password_is_incorrect(
    driver_config_client: TestClient,
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
            emailpassword.init(),
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
        ],
    )

    response_1 = sign_up_request(
        driver_config_client, "random@gmail.com", "validpass123"
    )
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"

    response_2 = driver_config_client.post(
        url="/auth/signin",
        json={
            "formFields": [
                {"id": "password", "value": "wrong_password"},
                {"id": "email", "value": "random@gmail.com"},
            ]
        },
    )

    assert response_2.status_code == 200
    dict_response = json.loads(response_2.text)
    assert dict_response["status"] == "WRONG_CREDENTIALS_ERROR"


@mark.asyncio
async def test_bad_input_not_a_JSON_to_signin_api(driver_config_client: TestClient):
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
            emailpassword.init(),
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
        ],
    )

    response_1 = sign_up_request(
        driver_config_client, "random@gmail.com", "validpass123"
    )
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"

    response_2 = driver_config_client.post(url="/auth/signin", json={"x": "y"})

    assert response_2.status_code == 200
    dict_response = json.loads(response_2.text)
    assert dict_response["status"] == "FIELD_ERROR"
    assert len(dict_response["formFields"]) == 2
    assert dict_response["formFields"][0]["error"] == "Field is not optional"


@mark.asyncio
async def test_bad_input_not_a_JSON_to_signin_API(driver_config_client: TestClient):
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
            emailpassword.init(),
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
        ],
    )

    response_1 = sign_up_request(
        driver_config_client, "random@gmail.com", "validpass123"
    )
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"

    response_2 = driver_config_client.post(url="/auth/signin", json={"x": "y"})

    assert response_2.status_code == 200
    dict_response = json.loads(response_2.text)
    assert dict_response["status"] == "FIELD_ERROR"
    assert len(dict_response["formFields"]) == 2
    assert dict_response["formFields"][0]["error"] == "Field is not optional"


@mark.asyncio
async def test_that_a_successful_signin_yields_a_session(
    driver_config_client: TestClient,
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
            emailpassword.init(),
            session.init(
                anti_csrf="VIA_TOKEN",
                get_token_transfer_method=lambda _, __, ___: "cookie",
            ),
        ],
    )

    response_1 = sign_up_request(
        driver_config_client, "random@gmail.com", "validpass123"
    )
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"

    response_2 = driver_config_client.post(
        url="/auth/signin",
        json={
            "formFields": [
                {"id": "password", "value": "validpass123"},
                {"id": "email", "value": "random@gmail.com"},
            ]
        },
    )

    assert response_2.status_code == 200

    cookies = extract_all_cookies(response_1)

    assert cookies["sAccessToken"] is not None
    assert cookies["sRefreshToken"] is not None
    assert response_2.headers.get("anti-csrf") is not None


@mark.asyncio
async def test_email_field_validation_error(driver_config_client: TestClient):
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
            emailpassword.init(),
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
        ],
    )

    response_1 = sign_up_request(
        driver_config_client, "random@gmail.com", "validpassword123"
    )
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"

    response_2 = driver_config_client.post(
        url="/auth/signin",
        json={
            "formFields": [
                {"id": "password", "value": "validpassword123"},
                {"id": "email", "value": "randomgmail.com"},
            ]
        },
    )

    assert response_2.status_code == 200
    dict_response = json.loads(response_2.text)
    assert dict_response["status"] == "FIELD_ERROR"


@mark.asyncio
async def test_formFields_has_no_email_field(driver_config_client: TestClient):
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
            emailpassword.init(),
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
        ],
    )

    response_1 = sign_up_request(
        driver_config_client, "random@gmail.com", "validpassword123"
    )
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"

    response_2 = driver_config_client.post(
        url="/auth/signin",
        json={"formFields": [{"id": "password", "value": "validpassword123"}]},
    )

    assert response_2.status_code == 200
    dict_response = json.loads(response_2.text)
    assert dict_response["status"] == "FIELD_ERROR"
    assert len(dict_response["formFields"]) == 1
    assert dict_response["formFields"][0]["error"] == "Field is not optional"
    assert dict_response["formFields"][0]["id"] == "email"


@mark.asyncio
async def test_formFields_has_no_password_field(driver_config_client: TestClient):
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
            emailpassword.init(),
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
        ],
    )

    response_1 = sign_up_request(
        driver_config_client, "random@gmail.com", "validpassword123"
    )
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"

    response_2 = driver_config_client.post(
        url="/auth/signin",
        json={"formFields": [{"id": "email", "value": "randomgmail.com"}]},
    )

    assert response_2.status_code == 200
    dict_response = json.loads(response_2.text)
    assert dict_response["status"] == "FIELD_ERROR"
    assert len(dict_response["formFields"]) == 2
    assert dict_response["formFields"][0]["error"] == "Field is not optional"
    assert dict_response["formFields"][1]["error"] == "Email is not valid"


@mark.asyncio
async def test_delete_user(driver_config_client: TestClient):
    init(
        supertokens_config=SupertokensConfig(get_new_core_app_url()),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth",
        ),
        framework="fastapi",
        recipe_list=[emailpassword.init(), session.init(anti_csrf="VIA_TOKEN")],
    )

    response_1 = sign_up_request(
        driver_config_client, "random@gmail.com", "validpass123"
    )
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"

    user_count = await get_user_count()
    assert user_count == 1

    version = await Querier.get_instance().get_api_version()

    if is_version_gte(version, "2.10"):
        await delete_user(dict_response["user"]["id"])
        user_count = await get_user_count()
        assert user_count == 0
    else:
        error_raised = True
        try:
            await delete_user(dict_response["user"]["id"])
            error_raised = False
        except Exception:
            pass

        assert error_raised


@mark.asyncio
async def test_optional_custom_field_without_input(driver_config_client: TestClient):
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
            emailpassword.init(
                sign_up_feature=emailpassword.InputSignUpFeature(
                    form_fields=[
                        emailpassword.InputFormField("test_field", optional=True)
                    ]
                )
            ),
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
        ],
    )

    response_1 = sign_up_request(
        driver_config_client, "random@gmail.com", "validpassword123"
    )
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"

    response_2 = driver_config_client.post(
        url="/auth/signin",
        json={
            "formFields": [
                {"id": "email", "value": "random@gmail.com"},
                {"id": "password", "value": "validpassword123"},
            ]
        },
    )

    assert response_2.status_code == 200
    dict_response = json.loads(response_2.text)
    assert dict_response["status"] == "OK"


@mark.asyncio
async def test_non_optional_custom_field_with_boolean_value(
    driver_config_client: TestClient,
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
            emailpassword.init(
                sign_up_feature=emailpassword.InputSignUpFeature(
                    form_fields=[
                        emailpassword.InputFormField("autoVerify", optional=False)
                    ]
                )
            ),
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
        ],
    )

    response_1 = driver_config_client.post(
        url="/auth/signup",
        headers={"Content-Type": "application/json"},
        json={
            "formFields": [
                {"id": "email", "value": "random@gmail.com"},
                {"id": "password", "value": "validpassword123"},
                {"id": "autoVerify", "value": False},
            ]
        },
    )
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"


@mark.asyncio
async def test_invalid_type_for_email_and_password(
    driver_config_client: TestClient,
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
            emailpassword.init(
                sign_up_feature=emailpassword.InputSignUpFeature(form_fields=[])
            ),
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
        ],
    )

    response_1 = driver_config_client.post(
        url="/auth/signup",
        headers={"Content-Type": "application/json"},
        json={
            "formFields": [
                {"id": "email", "value": 123},
                {"id": "password", "value": "validpassword123"},
            ]
        },
    )
    assert response_1.status_code == 400
    dict_response = json.loads(response_1.text)
    assert dict_response["message"] == "email value must be a string"

    response_1_signin = driver_config_client.post(
        url="/auth/signin",
        headers={"Content-Type": "application/json"},
        json={
            "formFields": [
                {"id": "email", "value": 123},
                {"id": "password", "value": "validpassword123"},
            ]
        },
    )
    assert response_1_signin.status_code == 400
    dict_response_signin = json.loads(response_1_signin.text)
    assert dict_response_signin["message"] == "email value must be a string"

    response_2 = driver_config_client.post(
        url="/auth/signup",
        headers={"Content-Type": "application/json"},
        json={
            "formFields": [
                {"id": "email", "value": "random@gmail.com"},
                {"id": "password", "value": 12345},
            ]
        },
    )
    assert response_2.status_code == 400
    dict_response = json.loads(response_2.text)
    assert dict_response["message"] == "password value must be a string"

    response_2_signin = driver_config_client.post(
        url="/auth/signin",
        headers={"Content-Type": "application/json"},
        json={
            "formFields": [
                {"id": "email", "value": "random@gmail.com"},
                {"id": "password", "value": 12345},
            ]
        },
    )
    assert response_2_signin.status_code == 400
    dict_response_signin = json.loads(response_2_signin.text)
    assert dict_response_signin["message"] == "password value must be a string"


@mark.asyncio
async def test_too_many_fields(driver_config_client: TestClient):
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
            emailpassword.init(
                sign_up_feature=emailpassword.InputSignUpFeature(
                    form_fields=[
                        emailpassword.InputFormField("test_field", optional=True)
                    ]
                )
            ),
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
        ],
    )

    response_1 = sign_up_request(
        driver_config_client, "random@gmail.com", "validpassword123"
    )
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "OK"

    response_2 = driver_config_client.post(
        url="/auth/signin",
        json={
            "formFields": [
                {"id": "email", "value": "random@gmail.com"},
                {"id": "password", "value": "validpassword123"},
                {"id": "test_field", "value": "gmail.com"},
                {"id": "extra_field", "value": "random@gmail.com"},
            ]
        },
    )

    assert response_2.status_code == 400
    dict_response = json.loads(response_2.text)
    assert dict_response["message"] == "Are you sending too many formFields?"


@mark.asyncio
async def test_non_optional_custom_field_without_input(
    driver_config_client: TestClient,
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
            emailpassword.init(
                sign_up_feature=emailpassword.InputSignUpFeature(
                    form_fields=[
                        emailpassword.InputFormField("test_field", optional=False)
                    ]
                )
            ),
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
        ],
    )

    response_1 = sign_up_request(
        driver_config_client, "random@gmail.com", "validpassword123"
    )
    assert response_1.status_code == 200
    dict_response = json.loads(response_1.text)
    assert dict_response["status"] == "FIELD_ERROR"
    assert len(dict_response["formFields"]) == 1
    assert dict_response["formFields"][0]["error"] == "Field is not optional"
    assert dict_response["formFields"][0]["id"] == "test_field"


# TODO add few more tests
