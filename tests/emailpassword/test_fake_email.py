# Copyright (c) 2026, VRAI Labs and/or its affiliates. All rights reserved.
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
from pytest import fixture, mark
from supertokens_python import init
from supertokens_python.asyncio import list_users_by_account_info
from supertokens_python.auth_utils import is_fake_email
from supertokens_python.framework.fastapi import get_middleware
from supertokens_python.recipe import emailpassword, session
from supertokens_python.recipe.emailpassword.asyncio import sign_up
from supertokens_python.recipe.emailpassword.interfaces import SignUpOkResult
from supertokens_python.types.base import AccountInfoInput

from tests.testclient import TestClientWithNoCookieJar as TestClient
from tests.utils import get_new_core_app_url, get_st_init_args

FAKE_EMAIL = "12345.github@stfakeemail.supertokens.com"


@mark.parametrize(
    "email",
    [
        FAKE_EMAIL,
        "12345.GITHUB@STFAKEEMAIL.SUPERTOKENS.COM",
        "12345.github@StFakeEmail.SuperTokens.com",
        f" {FAKE_EMAIL} ",
        "user.github.fakeemail.com",
        "USER.GITHUB.FAKEEMAIL.COM",
    ],
)
def test_is_fake_email_returns_true(email: str):
    assert is_fake_email(email) is True


@mark.parametrize(
    "email", ["user@example.com", "stfakeemail.supertokens.com@example.com"]
)
def test_is_fake_email_returns_false(email: str):
    assert is_fake_email(email) is False


@fixture(scope="function")
def client():
    init(
        **get_st_init_args(
            url=get_new_core_app_url(),
            recipe_list=[
                emailpassword.init(),
                session.init(get_token_transfer_method=lambda *_: "header"),  # type: ignore
            ],
        )
    )
    app = FastAPI()
    app.add_middleware(get_middleware())
    return TestClient(app)


def sign_in_request(client: TestClient, email: str, password: str):
    return client.post(
        "/auth/signin",
        json={
            "formFields": [
                {"id": "email", "value": email},
                {"id": "password", "value": password},
            ]
        },
    )


def sign_up_request(client: TestClient, email: str, password: str):
    return client.post(
        "/auth/signup",
        json={
            "formFields": [
                {"id": "email", "value": email},
                {"id": "password", "value": password},
            ]
        },
    )


@mark.asyncio
@mark.parametrize(
    "email",
    [FAKE_EMAIL, FAKE_EMAIL.upper(), "12345.GitHub@StFakeEmail.SuperTokens.com"],
)
async def test_signin_with_a_password_on_a_fake_email_is_not_a_first_factor(
    client: TestClient, email: str
):
    # e.g.: a password set up as a secondary factor for a third party user without an email
    sign_up_res = await sign_up("public", FAKE_EMAIL, "password123")
    assert isinstance(sign_up_res, SignUpOkResult)

    res = sign_in_request(client, email, "password123")

    assert res.status_code == 200
    assert res.json()["status"] == "WRONG_CREDENTIALS_ERROR"
    assert "st-access-token" not in res.headers


@mark.asyncio
async def test_signup_with_an_upper_cased_fake_email_is_rejected_like_the_lowercase_one(
    client: TestClient,
):
    lowercase_res = sign_up_request(
        client, "someone@stfakeemail.supertokens.com", "password123"
    )
    uppercase_res = sign_up_request(
        client, "someone@STFAKEEMAIL.SUPERTOKENS.COM", "password123"
    )

    assert lowercase_res.status_code == 200
    assert lowercase_res.json()["status"] == "FIELD_ERROR"
    assert uppercase_res.json() == lowercase_res.json()
    users = await list_users_by_account_info(
        "public", AccountInfoInput(email="someone@stfakeemail.supertokens.com")
    )
    assert len(users) == 0


@mark.asyncio
async def test_signin_with_a_regular_email_still_works(client: TestClient):
    await sign_up("public", "user@example.com", "password123")

    res = sign_in_request(client, "USER@example.com", "password123")

    assert res.json()["status"] == "OK"
