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
from typing import Optional, Dict, Any
from pytest import mark
from starlette.requests import Request
from starlette.testclient import TestClient
from supertokens_python import InputAppInfo, SupertokensConfig, init
from supertokens_python.framework.fastapi import get_middleware
from supertokens_python.recipe import jwt
from supertokens_python.recipe.jwt.interfaces import APIInterface, RecipeInterface
from supertokens_python.recipe.session.asyncio import create_new_session
from tests.utils import clean_st, reset, setup_st, start_st


pytestmark = mark.asyncio


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
        await create_new_session(request, "public", user_id, {}, {})
        return {"userId": user_id}

    return TestClient(app)


def apis_override_get_JWKS(param: APIInterface):
    param.disable_jwks_get = True
    return param


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


async def test_that_default_getJWKS_works_fine(driver_config_client: TestClient):
    custom_validity: Optional[int] = -1  # -1 means no override

    def func_override(oi: RecipeInterface):
        oi_get_jwks = oi.get_jwks

        async def get_jwks(user_context: Dict[str, Any]):
            res = await oi_get_jwks(user_context)
            if custom_validity != -1:
                res.validity_in_secs = custom_validity
            return res

        oi.get_jwks = get_jwks
        return oi

    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="supertokens.io",
        ),
        framework="fastapi",
        recipe_list=[jwt.init(override=jwt.OverrideConfig(functions=func_override))],
    )
    start_st()

    response = driver_config_client.get(url="/auth/jwt/jwks.json")

    # Default:
    assert response.status_code == 200
    data = response.json()
    assert data.keys() == {"keys"}
    assert len(data["keys"]) > 0
    assert data["keys"][0].keys() == {"kty", "kid", "n", "e", "alg", "use"}

    assert response.headers["cache-control"] == "max-age=60, must-revalidate"

    # Override cache control:
    custom_validity = 1
    response = driver_config_client.get(url="/auth/jwt/jwks.json")

    assert response.status_code == 200
    data = response.json()
    assert len(data["keys"]) > 0

    assert response.headers["cache-control"] == "max-age=1, must-revalidate"

    # Disable cache control:
    custom_validity = None
    response = driver_config_client.get(url="/auth/jwt/jwks.json")

    assert response.status_code == 200
    data = response.json()
    assert len(data["keys"]) > 0

    assert "cache-control" not in response.headers
