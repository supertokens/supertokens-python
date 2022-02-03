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
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pytest import fixture
from pytest import mark

from supertokens_python import init, SupertokensConfig, InputAppInfo
from supertokens_python.recipe import session, emailpassword
from supertokens_python.recipe.emailpassword.asyncio import sign_up
from supertokens_python.recipe.emailpassword.interfaces import APIInterface, RecipeInterface
from supertokens_python.recipe.session.interfaces import RecipeInterface as SRecipeInterface
from supertokens_python.framework.fastapi import Middleware
from .utils import (
    reset, setup_st, clean_st, start_st, sign_in_request
)

works = False
signUpContextWorks = False


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

    return TestClient(app)


@mark.asyncio
async def test_user_context(driver_config_client: TestClient):
    global works
    global signUpContextWorks

    def apis_override_email_password(param: APIInterface):
        og_sign_in_post = param.sign_in_post

        async def sign_in_post(form_fields, api_options, context):
            context = {
                'preSignInPOST': True
            }
            response = await og_sign_in_post(form_fields, api_options, context)
            if 'preSignInPOST' in context and \
                    'preSignIn' in context and \
                    'preCreateNewSession' in context and \
                    'postCreateNewSession' in context and \
                    'postSignIn' in context:
                global works
                works = True
            return response

        param.sign_in_post = sign_in_post
        return param

    def functions_override_email_password(param: RecipeInterface):
        og_sign_in = param.sign_in
        og_sign_up = param.sign_up

        async def sign_up_(email, password, context):
            if 'manualCall' in context:
                global signUpContextWorks
                signUpContextWorks = True
            response = await og_sign_up(email, password, context)
            return response

        async def sign_in(email, password, context):
            if 'preSignInPOST' in context:
                context['preSignIn'] = True
            response = await og_sign_in(email, password, context)
            if 'preSignInPOST' in context and \
                    'preSignIn' in context:
                context['postSignIn'] = True
            return response

        param.sign_in = sign_in
        param.sign_up = sign_up_
        return param

    def functions_override_session(param: SRecipeInterface):
        og_create_new_session = param.create_new_session

        async def create_new_session(request, user_id, context, _, __):
            if 'preSignInPOST' in context and \
                    'preSignIn' in context and \
                    'postSignIn' in context:
                context['preCreateNewSession'] = True
            response = await og_create_new_session(request, user_id, context, _, __)
            if 'preSignInPOST' in context and \
                    'preSignIn' in context and \
                    'postSignIn' in context and \
                    'preCreateNewSession' in context:
                context['postCreateNewSession'] = True
            return response

        param.create_new_session = create_new_session
        return param

    init(
        supertokens_config=SupertokensConfig('http://localhost:3567'),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io"
        ),
        framework='fastapi',
        recipe_list=[emailpassword.init(
            override=emailpassword.InputOverrideConfig(
                apis=apis_override_email_password,
                functions=functions_override_email_password
            )
        ), session.init(
            override=session.InputOverrideConfig(
                functions=functions_override_session
            )
        )]
    )
    start_st()

    await sign_up("random@gmail.com", "validpass123", {'manualCall': True})

    res = sign_in_request(
        driver_config_client,
        "random@gmail.com",
        "validpass123")
    assert res.status_code == 200
    assert works
    assert signUpContextWorks
