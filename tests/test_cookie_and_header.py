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

from supertokens_python.cookie_and_header import (
    set_cookie
)
from supertokens_python import SuperTokens
from fastapi import FastAPI
from fastapi.testclient import TestClient
from fastapi.responses import Response
from supertokens_python.utils import get_timestamp_ms
from pytest import fixture
from math import floor
from .utils import (
    get_cookie_from_response, get_unix_timestamp, reset, clean_st,
    setup_st, start_st, verify_within_5_second_diff
)

""" @fixtures
scope: function
Run once per test function

scope: class
Run once per test class, regardless of how many test methods are in the
"""


def setup_function(f):
    reset()
    clean_st()
    setup_st()


def teardown_function(f):
    reset()
    clean_st()


@fixture(scope='function')
def client():
    app = FastAPI()
    SuperTokens(app)

    @app.get('/')
    async def cookie_request(expiry: int):
        key = 'test'
        value = 'value'
        domain = 'localhost.org'
        secure = True
        http_only = False
        path = '/'
        expires = expiry
        same_site = 'none'
        response = Response()
        await set_cookie(
            response,
            key,
            value,
            expires,
            path,
            domain,
            secure,
            http_only,
            same_site)
        return response

    return TestClient(app)


def test_set_cookie(client: TestClient):
    start_st()
    expiry = get_timestamp_ms()
    response = client.get('/?expiry=' + str(expiry))
    test_cookie = get_cookie_from_response(response, 'test')
    assert test_cookie is not None
    assert test_cookie['value'] == 'value'
    assert test_cookie['domain'] == 'localhost.org'
    assert test_cookie['path'] == '/'
    assert test_cookie['samesite'] == 'none' or test_cookie['samesite'] == 'Lax'
    assert test_cookie['secure']
    assert test_cookie.get('httponly') is None
    assert verify_within_5_second_diff(
        get_unix_timestamp(test_cookie['expires']), floor(expiry / 1000)
    )
