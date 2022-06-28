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
from supertokens_python import InputAppInfo, SupertokensConfig, init
from supertokens_python.framework.fastapi import get_middleware
from supertokens_python.recipe import jwt
from supertokens_python.recipe.jwt.interfaces import APIInterface
from supertokens_python.recipe.session.asyncio import create_new_session
from tests.utils import clean_st, reset, setup_st, start_st


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

    @app.get("/login")
    async def login(request: Request):  # type: ignore
        user_id = "userId"
        await create_new_session(request, user_id, {}, {})
        return {"userId": user_id}

    return TestClient(app)


def apis_override_get_JWKS(param: APIInterface):
    param.disable_jwks_get = True
    return param


@mark.asyncio
async def test_that_default_getJWKS_api_does_not_work_when_disabled(
    driver_config_client: TestClient,
):
    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="supertokens.io",
        ),
        framework="fastapi",
        recipe_list=[
            jwt.init(override=jwt.OverrideConfig(apis=apis_override_get_JWKS))
        ],
    )
    start_st()

    response = driver_config_client.get(url="/auth/jwt/jwks.json")

    assert response.status_code == 404


@mark.asyncio
async def test_that_default_getJWKS_works_fine(driver_config_client: TestClient):
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

    response = driver_config_client.get(url="/auth/jwt/jwks.json")

    assert response.status_code == 200
    data = response.json()
    assert len(data["keys"]) > 0
