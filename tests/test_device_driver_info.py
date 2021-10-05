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

from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
from pytest import fixture, mark
from fastapi.requests import Request
from supertokens_python import SuperTokens, create_new_session, Session, supertokens_session
from supertokens_python.device_info import DeviceInfo
from .utils import (
    reset, setup_st, clean_st, start_st, extract_all_cookies
)
from supertokens_python.querier import Querier
from supertokens_python.constants import SESSION, HELLO, VERSION


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
    SuperTokens(app, cookie_domain='supertokens.io')

    @app.post('/login')
    async def login(request: Request):
        user_id = 'userId'
        await create_new_session(request, user_id, {}, {})
        return {'userId': user_id}

    @app.get('/info')
    def info(_: Session = Depends(supertokens_session)):
        return {}

    client = TestClient(app)
    return client


@mark.asyncio
async def test_driver_info_check_without_frontend_sdk():
    start_st()
    response = await Querier.get_instance().send_post_request(
        SESSION, {'userId': 'abc'}, True)
    assert response['userId'] == 'abc'
    assert 'deviceDriverInfo' in response
    assert response['deviceDriverInfo'] == {
        'driver': {
            'name': 'Fastapi',
            'version': VERSION},
        'frontendSDK': []}
    response = await Querier.get_instance().send_post_request(
        HELLO, {'userId': 'pqr'}, True)
    assert response['userId'] == 'pqr'
    assert 'deviceDriverInfo' not in response


def test_driver_info_check_with_frontend_sdk(client: TestClient):
    start_st()
    response_1 = client.post('/login')
    cookies_1 = extract_all_cookies(response_1)
    client.get('/info',
               cookies={
                   'sAccessToken': cookies_1['sAccessToken']['value'],
                   'sIdRefreshToken': cookies_1['sIdRefreshToken']['value']
               },
               headers={
                   'supertokens-sdk-name': 'ios',
                   'supertokens-sdk-version': '0.0.0'
               }
               )
    client.get('/info',
               cookies={
                   'sAccessToken': cookies_1['sAccessToken']['value'],
                   'sIdRefreshToken': cookies_1['sIdRefreshToken']['value']
               },
               headers={
                   'supertokens-sdk-name': 'android',
                   'supertokens-sdk-version': VERSION
               }
               )

    assert DeviceInfo.get_instance().get_frontend_sdk() == [{'name': 'ios', 'version': '0.0.0'},
                                                            {'name': 'android', 'version': VERSION}]
