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

from supertokens_python import init
from supertokens_python.querier import Querier
from supertokens_python.recipe import jwt
from supertokens_python.recipe.jwt import create_jwt
from supertokens_python.utils import utf_base64decode
from tests.utils import (
    reset, setup_st, clean_st, start_st
)


def setup_function(f):
    reset()
    clean_st()
    setup_st()


def teardown_function(f):
    reset()
    clean_st()


@mark.asyncio
async def test_that_sending_0_validity_throws_an_error():
    init({
        'supertokens': {
            'connection_uri': "http://localhost:3567",
        },
        'framework': 'fastapi',
        'app_info': {
            'app_name': "SuperTokens Demo",
            'api_domain': "http://api.supertokens.io",
            'website_domain': "supertokens.io",
        },
        'recipe_list': [jwt.init({})]
    })
    start_st()

    querier = Querier.get_instance()
    api_version = await querier.get_api_version()
    if api_version == "2.8":
        return

    is_exception = False
    try:
        await create_jwt({}, 0)
        raise Exception("should not come here")
    except Exception as e:
        print(e)
        is_exception = True

    assert is_exception


@mark.asyncio
async def test_that_sending_a_invalid_json_throws_an_error():
    init({
        'supertokens': {
            'connection_uri': "http://localhost:3567",
        },
        'framework': 'fastapi',
        'app_info': {
            'app_name': "SuperTokens Demo",
            'api_domain': "http://api.supertokens.io",
            'website_domain': "supertokens.io",
        },
        'recipe_list': [jwt.init({})]
    })
    start_st()

    querier = Querier.get_instance()
    api_version = await querier.get_api_version()
    if api_version == "2.8":
        return

    jwt_value = None
    try:
        await create_jwt("not a json", 0)
        raise Exception("should not come here")
    except Exception as e:
        print(e)
    assert jwt_value is None


@mark.asyncio
async def test_that_returned_JWT_uses_100_years_for_expiry_for_default_config():
    init({
        'supertokens': {
            'connection_uri': "http://localhost:3567",
        },
        'framework': 'fastapi',
        'app_info': {
            'app_name': "SuperTokens Demo",
            'api_domain': "http://api.supertokens.io",
            'website_domain': "supertokens.io",
        },
        'recipe_list': [jwt.init({})]
    })
    start_st()

    querier = Querier.get_instance()
    api_version = await querier.get_api_version()
    if api_version == "2.8":
        return

    time_rn = time.time()

    jwt_value = (await create_jwt({})).jwt.split(".")[1]
    decoded_jwt_value = utf_base64decode(jwt_value)

    target_expiry_duration = 3153600000
    jwt_expiry = json.loads(decoded_jwt_value)['exp']

    actual_expiry = jwt_expiry - time_rn
    difference_in_expiry_durations = abs(actual_expiry - target_expiry_duration)

    assert difference_in_expiry_durations < 5


@mark.asyncio
async def test_that_jwt_validity_is_same_as_validity_set_in_config():
    init({
        'supertokens': {
            'connection_uri': "http://localhost:3567",
        },
        'framework': 'fastapi',
        'app_info': {
            'app_name': "SuperTokens Demo",
            'api_domain': "http://api.supertokens.io",
            'website_domain': "supertokens.io",
        },
        'recipe_list': [jwt.init({"jwtValiditySeconds": 1000})]
    })
    start_st()

    querier = Querier.get_instance()
    api_version = await querier.get_api_version()
    if api_version == "2.8":
        return

    time_rn = time.time()

    jwt_value = (await create_jwt({})).jwt.split(".")[1]
    decoded_jwt_value = utf_base64decode(jwt_value)

    target_expiry_duration = 1000
    jwt_expiry = json.loads(decoded_jwt_value)['exp']

    actual_expiry = jwt_expiry - time_rn
    difference_in_expiry_durations = abs(actual_expiry - target_expiry_duration)

    assert difference_in_expiry_durations < 5


@mark.asyncio
async def test_that_jwt_validity_is_same_as_validity_passed_in_createJWT_function():
    init({
        'supertokens': {
            'connection_uri': "http://localhost:3567",
        },
        'framework': 'fastapi',
        'app_info': {
            'app_name': "SuperTokens Demo",
            'api_domain': "http://api.supertokens.io",
            'website_domain': "supertokens.io",
        },
        'recipe_list': [jwt.init({"jwtValiditySeconds": 1000})]
    })
    start_st()

    querier = Querier.get_instance()
    api_version = await querier.get_api_version()
    if api_version == "2.8":
        return

    time_rn = time.time()
    target_expiry_duration = 500

    jwt_value = (await create_jwt({}, target_expiry_duration)).jwt.split(".")[1]
    decoded_jwt_value = utf_base64decode(jwt_value)

    jwt_expiry = json.loads(decoded_jwt_value)['exp']

    actual_expiry = jwt_expiry - time_rn
    difference_in_expiry_durations = abs(actual_expiry - target_expiry_duration)

    assert difference_in_expiry_durations < 5
