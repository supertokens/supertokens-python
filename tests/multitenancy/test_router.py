# Copyright (c) 2023, VRAI Labs and/or its affiliates. All rights reserved.
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
from fastapi import FastAPI
from pytest import mark, fixture
from starlette.testclient import TestClient

from supertokens_python import init
from supertokens_python.framework.fastapi import get_middleware
from supertokens_python.recipe import session, emailpassword, dashboard
from tests.utils import setup_function, teardown_function, get_st_init_args, start_st

_ = setup_function
_ = teardown_function

pytestmark = mark.asyncio


@fixture(scope="function")
async def client():
    app = FastAPI()
    app.add_middleware(get_middleware())

    return TestClient(app)


async def test_emailpassword_router(client: TestClient):
    args = get_st_init_args(
        [
            session.init(get_token_transfer_method=lambda *_: "cookie"),  # type: ignore
            emailpassword.init(),
        ]
    )
    init(**args)
    start_st()

    res = client.post(
        "/auth/public/signup",
        headers={"Content-Type": "application/json"},
        json={
            "formFields": [
                {"id": "password", "value": "password1"},
                {"id": "email", "value": "test1@example.com"},
            ]
        },
    )

    assert res.status_code == 200
    assert res.json()["status"] == "OK"

    res = client.post(
        "/auth/signup",
        headers={"Content-Type": "application/json"},
        json={
            "formFields": [
                {"id": "password", "value": "password2"},
                {"id": "email", "value": "test2@example.com"},
            ]
        },
    )

    assert res.status_code == 200
    assert res.json()["status"] == "OK"


async def test_dashboard_apis_router(client: TestClient):
    args = get_st_init_args(
        [
            session.init(get_token_transfer_method=lambda *_: "cookie"),  # type: ignore
            emailpassword.init(),
            dashboard.init(),
        ]
    )
    init(**args)
    start_st()

    res = client.post(
        "/auth/public/dashboard/api/signin",
        headers={"Content-Type": "application/json"},
        json={
            "email": "test1@example.com",
            "password": "password1",
        },
    )

    assert res.status_code == 200

    res = client.post(
        "/auth/dashboard/api/signin",
        headers={"Content-Type": "application/json"},
        json={
            "email": "test1@example.com",
            "password": "password1",
        },
    )

    assert res.status_code == 200
