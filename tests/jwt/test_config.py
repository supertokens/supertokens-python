"""
Copyright (c) 2020, VRAI Labs and/or its affiliates. All rights reserved.

This software is licensed under the Apache License, Version 2.0 (the
"License") as published by the Apache Software Foundation.

You may not use this file except in compliance with the License. You may
obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.
"""

from pytest import mark
from supertokens_python import InputAppInfo, SupertokensConfig, init
from supertokens_python.recipe import jwt
from supertokens_python.recipe.jwt import JWTRecipe
from tests.utils import clean_st, reset, setup_st, start_st


def setup_function(_):
    reset()
    clean_st()
    setup_st()


def teardown_function(_):
    reset()
    clean_st()


@mark.asyncio
async def test_that_the_default_config_sets_values_correctly_for_JWT_recipe():
    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="supertokens.io",
        ),
        framework="fastapi",
        recipe_list=[jwt.init()],
    )
    start_st()

    jwt_recipe = JWTRecipe.get_instance()
    assert jwt_recipe.config.jwt_validity_seconds == 3153600000


@mark.asyncio
async def test_that_the_config_sets_values_correctly_for_JWT_recipe_when_jwt_validity_is_set():
    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="supertokens.io",
        ),
        framework="fastapi",
        recipe_list=[jwt.init(jwt_validity_seconds=24 * 60 * 60)],  # 24 hours
    )
    start_st()

    jwt_recipe = JWTRecipe.get_instance()
    assert jwt_recipe.config.jwt_validity_seconds == 24 * 60 * 60
