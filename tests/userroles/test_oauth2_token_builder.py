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
from unittest.mock import patch

from pytest import mark
from supertokens_python import init
from supertokens_python.recipe import oauth2provider, session, userroles
from supertokens_python.recipe.oauth2provider.recipe import OAuth2ProviderRecipe
from supertokens_python.recipe.webauthn.types.base import WebauthnInfo
from supertokens_python.types import LoginMethod, User

from tests.utils import (
    get_new_core_app_url,
    get_st_init_args,
    min_api_version,
)

pytestmark = mark.asyncio


def _make_user() -> User:
    user_id = "test-user-id"
    login_method = LoginMethod(
        recipe_id="emailpassword",
        recipe_user_id=user_id,
        tenant_ids=["public"],
        email="user@example.com",
        phone_number=None,
        third_party=None,
        webauthn=None,
        time_joined=0,
        verified=True,
    )
    return User(
        user_id=user_id,
        is_primary_user=True,
        tenant_ids=["public"],
        emails=["user@example.com"],
        phone_numbers=[],
        third_party=[],
        webauthn=WebauthnInfo(credential_ids=[]),
        login_methods=[login_method],
        time_joined=0,
    )


@min_api_version("2.14")
async def test_token_payload_builder_when_session_gone_and_no_role_scopes():
    """
    Regression: an offline_access OAuth refresh after the underlying session
    has been revoked or expired must not crash the token build flow when the
    requested scopes don't include "roles" or "permissions".

    Previously the userroles token_payload_builder raised
    `Exception("should never come here")` unconditionally on a missing session,
    turning every such refresh into a 500. Node has the same shape but only
    dereferences sessionInfo inside the role-scope branch, so this case was
    Python-only.
    """
    init(
        **get_st_init_args(
            url=get_new_core_app_url(),
            recipe_list=[
                session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
                userroles.init(),
                oauth2provider.init(),
            ],
        )
    )

    user = _make_user()
    scopes = ["offline_access", "mcp:ask_solve"]

    with patch(
        "supertokens_python.recipe.userroles.recipe.get_session_information",
        return_value=None,
    ):
        access_payload = (
            await OAuth2ProviderRecipe.get_instance().get_default_access_token_payload(
                user=user,
                scopes=scopes,
                session_handle="orphaned-handle",
                user_context={},
            )
        )
        id_payload = (
            await OAuth2ProviderRecipe.get_instance().get_default_id_token_payload(
                user=user,
                scopes=scopes,
                session_handle="orphaned-handle",
                user_context={},
            )
        )

    # Builder ran without raising. The userroles contributions should be the
    # explicit "no data" sentinels, not raise.
    assert access_payload.get("roles") is None
    assert access_payload.get("permissions") is None
    assert id_payload.get("roles") is None
    assert id_payload.get("permissions") is None


@min_api_version("2.14")
async def test_token_payload_builder_when_session_gone_with_role_scopes():
    """
    When the caller does request "roles" or "permissions" but the underlying
    session is gone, we still don't crash — we issue the token with empty
    role/permission lists rather than failing the OAuth flow. The alternative
    (returning OAuth `invalid_grant`) requires deeper plumbing through the
    oauth2provider recipe and is tracked separately.
    """
    init(
        **get_st_init_args(
            url=get_new_core_app_url(),
            recipe_list=[
                session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
                userroles.init(),
                oauth2provider.init(),
            ],
        )
    )

    user = _make_user()
    scopes = ["offline_access", "roles", "permissions"]

    with patch(
        "supertokens_python.recipe.userroles.recipe.get_session_information",
        return_value=None,
    ):
        access_payload = (
            await OAuth2ProviderRecipe.get_instance().get_default_access_token_payload(
                user=user,
                scopes=scopes,
                session_handle="orphaned-handle",
                user_context={},
            )
        )

    assert access_payload.get("roles") is None
    assert access_payload.get("permissions") is None
