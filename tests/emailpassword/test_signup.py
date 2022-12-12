# Copyright (c) 2021, VRAI Labs and/or its affiliates. All rights reserved.
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
import json
from fastapi.testclient import TestClient
from pytest import fixture, mark
from supertokens_python import init
from supertokens_python.framework.fastapi import get_middleware
from supertokens_python.recipe import emailpassword, session
from tests.utils import (
    get_st_init_args,
    setup_function,
    start_st,
    teardown_function,
    sign_up_request,
)

_ = setup_function  # type: ignore
_ = teardown_function  # type: ignore

pytestmark = mark.asyncio


@fixture(scope="function")
async def app():
    app = FastAPI()
    app.add_middleware(get_middleware())

    return TestClient(app)


async def test_field_error_on_existing_email_signup(app: TestClient):
    init_args = get_st_init_args([emailpassword.init(), session.init()])
    init(**init_args)
    start_st()

    response = json.loads(sign_up_request(app, "random@gmail.com", "validpass123").text)
    assert response["status"] == "OK"

    response = json.loads(sign_up_request(app, "random@gmail.com", "validpass123").text)
    assert response == {
        "status": "FIELD_ERROR",
        "formFields": [
            {
                "id": "email",
                "error": "This email already exists. Please sign in instead.",
            }
        ],
    }
