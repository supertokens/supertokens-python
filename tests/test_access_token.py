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
from supertokens_python.recipe.session.recipe import HandshakeInfo
from .utils import (
    reset, setup_st, clean_st, start_st, set_key_value_in_config, TEST_ENABLE_ANTI_CSRF_CONFIG_KEY
)
from pytest import mark
from supertokens_python.session_helper import create_new_session
from supertokens_python.access_token import get_info_from_access_token
from supertokens_python.exceptions import SuperTokensTryRefreshTokenError


def setup_function(f):
    reset()
    clean_st()
    setup_st()


def teardown_function(f):
    reset()
    clean_st()


@mark.asyncio
async def test_access_token_get_info_with_anti_csrf():
    start_st()
    jwt_key = (await HandshakeInfo.get_instance()).jwt_signing_public_key
    session_1 = await create_new_session('userId', {}, {})
    access_token_1 = session_1['accessToken']['token']
    get_info_from_access_token(access_token_1, jwt_key, False)
    get_info_from_access_token(access_token_1, jwt_key, True)
    try:
        get_info_from_access_token('random-string', jwt_key, True)
        assert False
    except SuperTokensTryRefreshTokenError:
        assert True
    try:
        get_info_from_access_token('random-string', jwt_key, False)
        assert False
    except SuperTokensTryRefreshTokenError:
        assert True
    try:
        get_info_from_access_token(access_token_1, 'random-key', False)
        assert False
    except SuperTokensTryRefreshTokenError:
        assert True


@mark.asyncio
async def test_access_token_get_info_without_anti_csrf():
    set_key_value_in_config(TEST_ENABLE_ANTI_CSRF_CONFIG_KEY, False)
    start_st()
    jwt_key = (await HandshakeInfo.get_instance()).jwt_signing_public_key
    session_1 = await create_new_session('userId', {}, {})
    access_token_1 = session_1['accessToken']['token']
    get_info_from_access_token(access_token_1, jwt_key, False)
    try:
        get_info_from_access_token(access_token_1, jwt_key, True)
        assert False
    except SuperTokensTryRefreshTokenError:
        assert True
    try:
        get_info_from_access_token('random-string', jwt_key, True)
        assert False
    except SuperTokensTryRefreshTokenError:
        assert True
    try:
        get_info_from_access_token('random-string', jwt_key, False)
        assert False
    except SuperTokensTryRefreshTokenError:
        assert True
    try:
        get_info_from_access_token(access_token_1, 'random-key', False)
        assert False
    except SuperTokensTryRefreshTokenError:
        assert True
