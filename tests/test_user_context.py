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
from typing import Any, Dict, List, Union

from pytest import fixture, mark
from supertokens_python import InputAppInfo, SupertokensConfig, init
from supertokens_python.framework.fastapi import get_middleware
from supertokens_python.recipe import emailpassword, session
from supertokens_python.recipe.emailpassword.asyncio import sign_up
from supertokens_python.recipe.emailpassword.interfaces import (
    APIInterface,
    APIOptions,
    RecipeInterface,
)
from supertokens_python.recipe.emailpassword.types import FormField
from supertokens_python.recipe.session.interfaces import (
    RecipeInterface as SRecipeInterface,
)

from fastapi import FastAPI
from fastapi.testclient import TestClient

from .utils import clean_st, reset, setup_st, sign_in_request, start_st

works = False
signUpContextWorks = False


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
async def test_user_context(driver_config_client: TestClient):
    global works
    global signUpContextWorks

    def apis_override_email_password(param: APIInterface):
        og_sign_in_post = param.sign_in_post

        async def sign_in_post(
            form_fields: List[FormField],
            api_options: APIOptions,
            user_context: Dict[str, Any],
        ):
            user_context = {"preSignInPOST": True}
            response = await og_sign_in_post(form_fields, api_options, user_context)
            if (
                "preSignInPOST" in user_context
                and "preSignIn" in user_context
                and "preCreateNewSession" in user_context
                and "postCreateNewSession" in user_context
                and "postSignIn" in user_context
            ):
                global works
                works = True
            return response

        param.sign_in_post = sign_in_post
        return param

    def functions_override_email_password(param: RecipeInterface):
        og_sign_in = param.sign_in
        og_sign_up = param.sign_up

        async def sign_up_(email: str, password: str, user_context: Dict[str, Any]):
            if "manualCall" in user_context:
                global signUpContextWorks
                signUpContextWorks = True
            response = await og_sign_up(email, password, user_context)
            return response

        async def sign_in(email: str, password: str, user_context: Dict[str, Any]):
            if "preSignInPOST" in user_context:
                user_context["preSignIn"] = True
            response = await og_sign_in(email, password, user_context)
            if "preSignInPOST" in user_context and "preSignIn" in user_context:
                user_context["postSignIn"] = True
            return response

        param.sign_in = sign_in
        param.sign_up = sign_up_
        return param

    def functions_override_session(param: SRecipeInterface):
        og_create_new_session = param.create_new_session

        async def create_new_session(
            request: Any,
            user_id: str,
            access_token_payload: Union[None, Dict[str, Any]],
            session_data: Union[None, Dict[str, Any]],
            user_context: Dict[str, Any],
        ):
            if (
                "preSignInPOST" in user_context
                and "preSignIn" in user_context
                and "postSignIn" in user_context
            ):
                user_context["preCreateNewSession"] = True
            response = await og_create_new_session(
                request, user_id, access_token_payload, session_data, user_context
            )
            if (
                "preSignInPOST" in user_context
                and "preSignIn" in user_context
                and "postSignIn" in user_context
                and "preCreateNewSession" in user_context
            ):
                user_context["postCreateNewSession"] = True
            return response

        param.create_new_session = create_new_session
        return param

    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
        ),
        framework="fastapi",
        recipe_list=[
            emailpassword.init(
                override=emailpassword.InputOverrideConfig(
                    apis=apis_override_email_password,
                    functions=functions_override_email_password,
                )
            ),
            session.init(
                override=session.InputOverrideConfig(
                    functions=functions_override_session
                )
            ),
        ],
    )
    start_st()

    await sign_up("random@gmail.com", "validpass123", {"manualCall": True})

    res = sign_in_request(driver_config_client, "random@gmail.com", "validpass123")
    assert res.status_code == 200
    assert works
    assert signUpContextWorks
