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
Plan 5 regression tests:

- N18: get_default_user_info_payload should not emit `phoneNumber: None`
  for users without a phone. Matches the behavior of the access-token
  and id-token builders, and Node's omit-on-undefined serialization.
- Sync/async signature parity for create_token_for_client_credentials:
  client_secret is Optional[str] in both wrappers.
"""

import inspect

from pytest import mark
from supertokens_python import init
from supertokens_python.recipe import oauth2provider, session
from supertokens_python.recipe.oauth2provider import asyncio as oauth_async
from supertokens_python.recipe.oauth2provider import syncio as oauth_sync
from supertokens_python.recipe.oauth2provider.recipe import OAuth2ProviderRecipe
from supertokens_python.recipe.webauthn.types.base import WebauthnInfo
from supertokens_python.types import LoginMethod, User

from tests.utils import (
    get_new_core_app_url,
    get_st_init_args,
    min_api_version,
)

pytestmark = mark.asyncio


def _user_without_phone() -> User:
    user_id = "user-no-phone"
    return User(
        user_id=user_id,
        is_primary_user=True,
        tenant_ids=["public"],
        emails=["x@example.com"],
        phone_numbers=[],
        third_party=[],
        webauthn=WebauthnInfo(credential_ids=[]),
        login_methods=[
            LoginMethod(
                recipe_id="emailpassword",
                recipe_user_id=user_id,
                tenant_ids=["public"],
                email="x@example.com",
                phone_number=None,
                third_party=None,
                webauthn=None,
                time_joined=0,
                verified=True,
            )
        ],
        time_joined=0,
    )


@min_api_version("2.14")
async def test_user_info_payload_omits_phone_number_when_absent():
    """N18: when the user has no phone, phoneNumber must be absent from the
    user_info payload — not present as null. Matches the access-token and
    id-token builders, and Node's serialization."""
    init(
        **get_st_init_args(
            url=get_new_core_app_url(),
            recipe_list=[
                session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
                oauth2provider.init(),
            ],
        )
    )

    payload = await OAuth2ProviderRecipe.get_instance().get_default_user_info_payload(
        user=_user_without_phone(),
        access_token_payload={"sub": "user-no-phone"},
        scopes=["phoneNumber"],
        tenant_id="public",
        user_context={},
    )

    assert "phoneNumber" not in payload
    # The companion `phoneNumber_verified` key still gets emitted (matches
    # Node's behavior of emitting the verified flag even when phone is
    # absent).
    assert payload.get("phoneNumber_verified") is False
    assert payload.get("phoneNumbers") == []


def test_create_token_for_client_credentials_sync_async_signature_parity():
    """The async and sync wrappers for create_token_for_client_credentials
    must have the same client_secret signature. Previously async accepted
    Optional[str] but sync required str."""
    async_sig = inspect.signature(oauth_async.create_token_for_client_credentials)
    sync_sig = inspect.signature(oauth_sync.create_token_for_client_credentials)

    # Annotations are strings under `from __future__ import annotations`.
    assert (
        async_sig.parameters["client_secret"].annotation
        == sync_sig.parameters["client_secret"].annotation
    )
    assert (
        async_sig.parameters["client_secret"].default
        == sync_sig.parameters["client_secret"].default
    )
    assert sync_sig.parameters["client_secret"].default is None
