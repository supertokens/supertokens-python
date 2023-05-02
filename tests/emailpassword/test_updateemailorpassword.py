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
from typing import Any, Union

from fastapi import FastAPI
from fastapi.requests import Request
from fastapi.testclient import TestClient
from pytest import fixture, mark
from supertokens_python import InputAppInfo, SupertokensConfig, init
from supertokens_python.framework.fastapi import get_middleware
from supertokens_python.recipe import emailpassword, emailverification, session
from supertokens_python.recipe.session import SessionContainer
from supertokens_python.recipe.session.asyncio import (
    create_new_session,
    get_session,
    refresh_session,
)
from tests.utils import (
    setup_function,
    sign_up_request,
    start_st,
    teardown_function,
)
from supertokens_python.recipe.emailpassword import InputFormField

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


async def test_update_email_or_password_with_default_validator(
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
            session.init(
                anti_csrf="VIA_TOKEN",
                get_token_transfer_method=lambda _, __, ___: "cookie",
            ),
            emailverification.init("OPTIONAL"),
            emailpassword.init(),
        ],
    )
    start_st()

    response_1 = sign_up_request(driver_config_client, "test@gmail.com", "testPass123")

    dict_response = json.loads(response_1.text)

    user_id = dict_response["user"]["id"]

    r = await emailpassword.EmailPasswordRecipe.get_instance().recipe_implementation.update_email_or_password(
        user_id=user_id,
        email=None,
        password="test",
        user_context={},
        apply_password_policy=None,
    )

    assert (
        r.failure_reason  # type: ignore
        == "Password must contain at least 8 characters, including a number"
    )


async def test_update_email_or_password_with_custom_validator(
    driver_config_client: TestClient,
):
    async def validate_pass(value: Any):
        # Validation method to make sure that age >= 18
        if len(value) < 3:
            return "Password should be at least 3 chars long"
        return None  # means that there is no error

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
            session.init(
                anti_csrf="VIA_TOKEN",
                get_token_transfer_method=lambda _, __, ___: "cookie",
            ),
            emailverification.init("OPTIONAL"),
            emailpassword.init(
                sign_up_feature=emailpassword.InputSignUpFeature(
                    form_fields=[InputFormField(id="password", validate=validate_pass)]
                )
            ),
        ],
    )
    start_st()

    response_1 = sign_up_request(driver_config_client, "test@gmail.com", "testPass123")

    dict_response = json.loads(response_1.text)

    user_id = dict_response["user"]["id"]

    r = await emailpassword.EmailPasswordRecipe.get_instance().recipe_implementation.update_email_or_password(
        user_id=user_id,
        email=None,
        password="te",
        user_context={},
        apply_password_policy=None,
    )
    assert r.failure_reason == "Password should be at least 3 chars long"  # type: ignore
