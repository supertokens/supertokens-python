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
"""
Plan 2 regression tests: when the SuperTokens core returns
`{"status": "OAUTH_ERROR", ...}` for an OAuth2 admin call, the recipe
must surface an `ErrorOAuth2Response` instead of crashing or silently
treating the error as inactive/unknown. Public type signatures were
widened to admit the error variant in 0.32.0.
"""

from unittest.mock import AsyncMock, patch

from pytest import mark
from supertokens_python import init
from supertokens_python.recipe import oauth2provider, session
from supertokens_python.recipe.oauth2provider.interfaces import (
    ActiveTokenResponse,
    ErrorOAuth2Response,
    InactiveTokenResponse,
    RedirectResponse,
)
from supertokens_python.recipe.oauth2provider.recipe import OAuth2ProviderRecipe

from tests.utils import (
    get_new_core_app_url,
    get_st_init_args,
    min_api_version,
)

pytestmark = mark.asyncio


def _init_recipe():
    init(
        **get_st_init_args(
            url=get_new_core_app_url(),
            recipe_list=[
                session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
                oauth2provider.init(),
            ],
        )
    )


@min_api_version("2.14")
async def test_introspect_token_surfaces_oauth_error():
    """The core can return OAUTH_ERROR (e.g. core misconfiguration). Previously
    Python collapsed this onto the inactive branch, which masked backend
    failures as 'token inactive'. We now return ErrorOAuth2Response so
    callers can distinguish."""
    _init_recipe()

    core_response = {
        "status": "OAUTH_ERROR",
        "statusCode": 500,
        "error": "server_error",
        "errorDescription": "internal server error",
    }

    with patch(
        "supertokens_python.querier.Querier.send_post_request",
        new=AsyncMock(return_value=core_response),
    ):
        result = await OAuth2ProviderRecipe.get_instance().recipe_implementation.introspect_token(
            token="st_rt_abc",
            scopes=None,
            user_context={},
        )

    assert isinstance(result, ErrorOAuth2Response)
    assert result.error == "server_error"
    assert result.error_description == "internal server error"
    assert result.status_code == 500


@min_api_version("2.14")
async def test_introspect_token_active_branch_unchanged():
    """Active introspection still returns ActiveTokenResponse — the new
    error branch must not regress the OK path."""
    _init_recipe()

    with patch(
        "supertokens_python.querier.Querier.send_post_request",
        new=AsyncMock(
            return_value={"active": True, "sub": "user-1", "scope": "openid"}
        ),
    ):
        result = await OAuth2ProviderRecipe.get_instance().recipe_implementation.introspect_token(
            token="st_rt_abc",
            scopes=None,
            user_context={},
        )

    assert isinstance(result, ActiveTokenResponse)
    assert result.payload["sub"] == "user-1"


@min_api_version("2.14")
async def test_introspect_token_inactive_branch_unchanged():
    """Inactive introspection still returns InactiveTokenResponse."""
    _init_recipe()

    with patch(
        "supertokens_python.querier.Querier.send_post_request",
        new=AsyncMock(return_value={"active": False}),
    ):
        result = await OAuth2ProviderRecipe.get_instance().recipe_implementation.introspect_token(
            token="st_rt_abc",
            scopes=None,
            user_context={},
        )

    assert isinstance(result, InactiveTokenResponse)


@min_api_version("2.14")
async def test_accept_login_request_surfaces_oauth_error():
    """A consent challenge can expire between issuance and acceptance.
    Previously Python KeyError'd on response['redirectTo']; now we return
    ErrorOAuth2Response."""
    _init_recipe()

    core_response = {
        "status": "OAUTH_ERROR",
        "statusCode": 410,
        "error": "invalid_request",
        "errorDescription": "challenge expired",
    }

    with patch(
        "supertokens_python.querier.Querier.send_put_request",
        new=AsyncMock(return_value=core_response),
    ):
        result = await OAuth2ProviderRecipe.get_instance().recipe_implementation.accept_login_request(
            challenge="some-challenge",
            acr=None,
            amr=None,
            context=None,
            extend_session_lifespan=None,
            identity_provider_session_id=None,
            subject="user-1",
            user_context={},
        )

    assert isinstance(result, ErrorOAuth2Response)
    assert result.error == "invalid_request"
    assert result.error_description == "challenge expired"
    assert result.status_code == 410


@min_api_version("2.14")
async def test_accept_login_request_ok_branch_unchanged():
    _init_recipe()

    with patch(
        "supertokens_python.querier.Querier.send_put_request",
        new=AsyncMock(return_value={"redirectTo": "http://example.com/callback"}),
    ):
        result = await OAuth2ProviderRecipe.get_instance().recipe_implementation.accept_login_request(
            challenge="some-challenge",
            acr=None,
            amr=None,
            context=None,
            extend_session_lifespan=None,
            identity_provider_session_id=None,
            subject="user-1",
            user_context={},
        )

    assert isinstance(result, RedirectResponse)
    assert "example.com/callback" in result.redirect_to


@min_api_version("2.14")
async def test_reject_login_request_surfaces_oauth_error():
    _init_recipe()

    with patch(
        "supertokens_python.querier.Querier.send_put_request",
        new=AsyncMock(
            return_value={
                "status": "OAUTH_ERROR",
                "statusCode": 410,
                "error": "invalid_request",
                "errorDescription": "challenge expired",
            }
        ),
    ):
        result = await OAuth2ProviderRecipe.get_instance().recipe_implementation.reject_login_request(
            challenge="some-challenge",
            error=ErrorOAuth2Response(
                error="access_denied",
                error_description="user rejected consent",
            ),
            user_context={},
        )

    assert isinstance(result, ErrorOAuth2Response)
    assert result.error == "invalid_request"


@min_api_version("2.14")
async def test_accept_consent_request_surfaces_oauth_error():
    _init_recipe()

    with patch(
        "supertokens_python.querier.Querier.send_put_request",
        new=AsyncMock(
            return_value={
                "status": "OAUTH_ERROR",
                "statusCode": 410,
                "error": "invalid_request",
                "errorDescription": "consent challenge expired",
            }
        ),
    ):
        result = await OAuth2ProviderRecipe.get_instance().recipe_implementation.accept_consent_request(
            challenge="some-challenge",
            context=None,
            grant_access_token_audience=None,
            grant_scope=None,
            handled_at=None,
            tenant_id="public",
            rsub="user-1",
            session_handle="handle-1",
            initial_access_token_payload=None,
            initial_id_token_payload=None,
            user_context={},
        )

    assert isinstance(result, ErrorOAuth2Response)
    assert result.error_description == "consent challenge expired"


@min_api_version("2.14")
async def test_reject_consent_request_surfaces_oauth_error():
    _init_recipe()

    with patch(
        "supertokens_python.querier.Querier.send_put_request",
        new=AsyncMock(
            return_value={
                "status": "OAUTH_ERROR",
                "statusCode": 410,
                "error": "invalid_request",
                "errorDescription": "consent challenge expired",
            }
        ),
    ):
        result = await OAuth2ProviderRecipe.get_instance().recipe_implementation.reject_consent_request(
            challenge="some-challenge",
            error=ErrorOAuth2Response(
                error="access_denied",
                error_description="user rejected",
            ),
            user_context={},
        )

    assert isinstance(result, ErrorOAuth2Response)
    assert result.error_description == "consent challenge expired"
