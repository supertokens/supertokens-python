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

from _pytest.fixtures import fixture
from fastapi import FastAPI
from pytest import mark
from starlette.requests import Request
from starlette.testclient import TestClient

from supertokens_python import init
from supertokens_python.framework.fastapi import Middleware
from supertokens_python.querier import Querier
from supertokens_python.recipe import jwt
from supertokens_python.recipe.jwt import create_jwt
from supertokens_python.recipe.jwt.interfaces import RecipeInterface
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


@fixture(scope='function')
async def driver_config_client():
    app = FastAPI()
    app.add_middleware(Middleware)

    @app.post('/jwtcreate')
    async def jwt_create(request: Request):
        payload = (await request.json())['payload']
        response = await create_jwt(payload, 1000)
        return response

    return TestClient(app)


@mark.asyncio
async def test_that_default_getJWKS_api_does_not_work_when_disabled(driver_config_client: TestClient):
    created_jwt = None
    jwt_keys = None

    def custom_functions(param: RecipeInterface):
        temp = param.get_JWKS

        async def get_jwks():
            response = await temp()

            if response.status == "OK":
                nonlocal jwt_keys
                jwt_keys = response.keys

            return response

        param.create_jwt = get_jwks

        temp1 = param.create_jwt

        async def create_jwt(input):
            response = await temp1(input)

            if response.status == "OK":
                nonlocal created_jwt
                created_jwt = response.jwt

            return response

        param.create_jwt = create_jwt
        param.get_JWKS = get_jwks
        return param

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
        'recipe_list': [jwt.init({'override': {
            'functions': custom_functions
        }, })]
    })
    start_st()

    querier = Querier.get_instance()
    api_version = await querier.get_api_version()
    if api_version == "2.8":
        return

    response = driver_config_client.post(
        url="/jwtcreate",
        json={
            'payload': {
                "someKey": "key"
            }
        }
    )

    assert response is None
    assert response.json()['jwt'] == created_jwt

    response = driver_config_client.get(
        url="/auth/jwt/jwks.json"
    )

    assert response is None
    assert response.json()['jwt'] == created_jwt
