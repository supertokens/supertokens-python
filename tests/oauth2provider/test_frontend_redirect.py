# Copyright (c) 2026, VRAI Labs and/or its affiliates. All rights reserved.
#
# This software is licensed under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
from unittest.mock import MagicMock
from typing import Union

from pytest import mark

from supertokens_python.recipe.oauth2provider.interfaces import (
    FrontendRedirectionURLTypeLogin,
    FrontendRedirectionURLTypeLogoutConfirmation,
    FrontendRedirectionURLTypePostLogoutFallback,
    FrontendRedirectionURLTypeTryRefresh,
)
from supertokens_python.recipe.oauth2provider.recipe_implementation import (
    RecipeImplementation,
)
from supertokens_python.supertokens import AppInfo

pytestmark = mark.asyncio

FrontendRedirectParams = Union[
    FrontendRedirectionURLTypeTryRefresh,
    FrontendRedirectionURLTypeLogoutConfirmation,
    FrontendRedirectionURLTypePostLogoutFallback,
]


def get_recipe_implementation() -> RecipeImplementation:
    app_info = AppInfo(
        app_name="test-app",
        api_domain="https://api.example.com",
        website_domain="https://www.example.com",
        framework="fastapi",
        api_gateway_path="",
        api_base_path="/auth",
        website_base_path="/account/login",
        mode=None,
        origin=None,
    )
    return RecipeImplementation(
        querier=MagicMock(),
        app_info=app_info,
        get_default_access_token_payload=MagicMock(),
        get_default_id_token_payload=MagicMock(),
        get_default_user_info_payload=MagicMock(),
    )


async def test_frontend_login_redirect_uses_website_base_path():
    recipe_implementation = get_recipe_implementation()

    redirect_to = await recipe_implementation.get_frontend_redirection_url(
        FrontendRedirectionURLTypeLogin(
            login_challenge="login-challenge",
            tenant_id="public",
            force_fresh_auth=False,
        ),
        user_context={},
    )

    assert redirect_to == (
        "https://www.example.com/account/login?loginChallenge=login-challenge"
    )


@mark.parametrize(
    "params, expected_suffix",
    [
        (
            FrontendRedirectionURLTypeTryRefresh("login-challenge"),
            "/try-refresh?loginChallenge=login-challenge",
        ),
        (
            FrontendRedirectionURLTypeLogoutConfirmation("logout-challenge"),
            "/oauth/logout?logoutChallenge=logout-challenge",
        ),
        (
            FrontendRedirectionURLTypePostLogoutFallback(),
            "",
        ),
    ],
)
async def test_frontend_redirects_use_website_base_path(
    params: FrontendRedirectParams, expected_suffix: str
):
    recipe_implementation = get_recipe_implementation()

    redirect_to = await recipe_implementation.get_frontend_redirection_url(
        params,
        user_context={},
    )

    assert redirect_to == f"https://www.example.com/account/login{expected_suffix}"
