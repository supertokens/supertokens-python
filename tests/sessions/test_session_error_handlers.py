# Copyright (c) 2024, VRAI Labs and/or its affiliates. All rights reserved.
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

from typing import List

from fastapi import FastAPI
from fastapi.requests import Request
from pytest import fixture, mark
from tests.testclient import TestClientWithNoCookieJar as TestClient

from supertokens_python import init
from supertokens_python.framework import BaseRequest, BaseResponse
from supertokens_python.framework.fastapi.fastapi_middleware import get_middleware
from supertokens_python.recipe import session
from supertokens_python.recipe.session import InputErrorHandlers


from tests.utils import clean_st, reset, setup_st, start_st
from supertokens_python.recipe.session.exceptions import (
    ClaimValidationError,
    ClearDuplicateSessionCookiesError,
    InvalidClaimsError,
    TokenTheftError,
    TryRefreshTokenError,
    UnauthorisedError,
)
from tests.utils import get_st_init_args

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

    @app.post("/test/unauthorized")
    async def test_unauthorized(_request: Request):  # type: ignore
        raise UnauthorisedError("")

    @app.post("/test/try-refresh")
    async def test_try_refresh(_request: Request):  # type: ignore
        raise TryRefreshTokenError("")

    @app.post("/test/token-theft")
    async def test_token_theft(_request: Request):  # type: ignore
        raise TokenTheftError("", "")

    @app.post("/test/claim-validation")
    async def test_claim_validation(_request: Request):  # type: ignore
        raise InvalidClaimsError("", [])

    @app.post("/test/clear-duplicate-session")
    async def test_clear_duplicate_session(_request: Request):  # type: ignore
        raise ClearDuplicateSessionCookiesError("")

    return TestClient(app)


async def test_session_error_handlers_are_getting_overridden(
    driver_config_client: TestClient,
):
    def unauthorised_f(_req: BaseRequest, _message: str, res: BaseResponse):
        res.set_status_code(401)
        res.set_json_content({"message": "unauthorized from errorHandler"})
        return res

    def token_theft_f(
        _req: BaseRequest, _session_handle: str, _user_id: str, res: BaseResponse
    ):
        res.set_status_code(403)
        res.set_json_content({"message": "token theft detected from errorHandler"})
        return res

    def try_refresh_f(_req: BaseRequest, _message: str, res: BaseResponse):
        res.set_status_code(401)
        res.set_json_content({"message": "try refresh session from errorHandler"})
        return res

    def invalid_claim_f(
        _req: BaseRequest,
        _claim_validation_errors: List[ClaimValidationError],
        res: BaseResponse,
    ):
        res.set_status_code(403)
        res.set_json_content({"message": "invalid claim from errorHandler"})
        return res

    def clear_duplicate_session_f(_req: BaseRequest, _message: str, res: BaseResponse):
        res.set_status_code(200)
        res.set_json_content(
            {"message": "clear duplicate session cookies from errorHandler"}
        )
        return res

    init_args = get_st_init_args(
        [
            session.init(
                anti_csrf="VIA_TOKEN",
                get_token_transfer_method=lambda _, __, ___: "cookie",
                error_handlers=InputErrorHandlers(
                    on_unauthorised=unauthorised_f,
                    on_try_refresh_token=try_refresh_f,
                    on_token_theft_detected=token_theft_f,
                    on_invalid_claim=invalid_claim_f,
                    on_clear_duplicate_session_cookies=clear_duplicate_session_f,
                ),
            )
        ]
    )
    init(**init_args)
    start_st()

    res = driver_config_client.post("test/unauthorized")
    assert res.status_code == 401
    assert res.json() == {"message": "unauthorized from errorHandler"}

    res = driver_config_client.post("test/try-refresh")
    assert res.status_code == 401
    assert res.json() == {"message": "try refresh session from errorHandler"}

    res = driver_config_client.post("test/token-theft")
    assert res.status_code == 403
    assert res.json() == {"message": "token theft detected from errorHandler"}

    res = driver_config_client.post("test/claim-validation")
    assert res.status_code == 403
    assert res.json() == {"message": "invalid claim from errorHandler"}

    res = driver_config_client.post("test/clear-duplicate-session")
    assert res.status_code == 200
    assert res.json() == {
        "message": "clear duplicate session cookies from errorHandler"
    }
