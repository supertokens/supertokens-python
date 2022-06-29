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
import json
import time

from pytest import mark
from supertokens_python import InputAppInfo, SupertokensConfig, init
from supertokens_python.recipe import jwt
from supertokens_python.recipe.jwt.asyncio import create_jwt
from supertokens_python.recipe.jwt.interfaces import CreateJwtOkResult
from supertokens_python.utils import utf_base64decode
from tests.utils import clean_st, reset, setup_st, start_st


def setup_function(_):
    reset()
    clean_st()
    setup_st()


def teardown_function(_):
    reset()
    clean_st()


@mark.asyncio
async def test_that_sending_0_validity_throws_an_error():
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

    is_exception = False
    try:
        await create_jwt({}, 0)
    except Exception:
        is_exception = True

    assert is_exception


@mark.asyncio
async def test_that_sending_a_invalid_json_throws_an_error():
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

    jwt_value = None
    is_exception = False
    try:
        await create_jwt("not a json", 0)  # type: ignore
    except Exception:
        is_exception = True

    assert jwt_value is None
    assert is_exception


@mark.asyncio
async def test_that_returned_JWT_uses_100_years_for_expiry_for_default_config():
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

    time_rn = time.time()
    result = await create_jwt({})
    assert isinstance(result, CreateJwtOkResult)
    jwt_value = result.jwt.split(".")[1]
    decoded_jwt_value = utf_base64decode(jwt_value)

    target_expiry_duration = 3153600000
    jwt_expiry = json.loads(decoded_jwt_value)["exp"]

    actual_expiry = jwt_expiry - time_rn
    difference_in_expiry_durations = abs(actual_expiry - target_expiry_duration)

    assert difference_in_expiry_durations < 5


@mark.asyncio
async def test_that_jwt_validity_is_same_as_validity_set_in_config():
    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="supertokens.io",
        ),
        framework="fastapi",
        recipe_list=[jwt.init(jwt_validity_seconds=1000)],
    )
    start_st()

    time_rn = time.time()

    result = await create_jwt({})
    assert isinstance(result, CreateJwtOkResult)
    jwt_value = result.jwt.split(".")[1]
    decoded_jwt_value = utf_base64decode(jwt_value)

    target_expiry_duration = 1000
    jwt_expiry = json.loads(decoded_jwt_value)["exp"]

    actual_expiry = jwt_expiry - time_rn
    difference_in_expiry_durations = abs(actual_expiry - target_expiry_duration)

    assert difference_in_expiry_durations < 5


@mark.asyncio
async def test_that_jwt_validity_is_same_as_validity_passed_in_createJWT_function():
    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="supertokens.io",
        ),
        framework="fastapi",
        recipe_list=[jwt.init(jwt_validity_seconds=1000)],
    )
    start_st()

    time_rn = time.time()
    target_expiry_duration = 500

    result = await create_jwt({}, target_expiry_duration)
    assert isinstance(result, CreateJwtOkResult)
    jwt_value = result.jwt.split(".")[1]
    decoded_jwt_value = utf_base64decode(jwt_value)

    jwt_expiry = json.loads(decoded_jwt_value)["exp"]

    actual_expiry = jwt_expiry - time_rn
    difference_in_expiry_durations = abs(actual_expiry - target_expiry_duration)

    assert difference_in_expiry_durations < 5
