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
Plan 3 regression tests: validate_oauth2_access_token must
(a) use the JWK's declared algorithm rather than hardcoded RS256, and
(b) raise a clear key/signature error when no matching JWK is found —
not fall through to 'Wrong token type'.
"""

from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

from pytest import mark, raises
from supertokens_python import init
from supertokens_python.recipe import oauth2provider, session
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
async def test_validate_access_token_raises_clear_error_when_no_matching_key():
    """When the JWKS doesn't have a matching key for the token's kid we must
    surface a key/signature error, not 'Wrong token type'. Previously the
    empty-keys path silently produced an empty payload and then failed the
    payload['stt'] != 1 check, masking the real cause."""
    _init_recipe()

    fake_token_obj = MagicMock()
    fake_token_obj.kid = "missing-kid"

    with (
        patch(
            "supertokens_python.recipe.oauth2provider.recipe_implementation.parse_jwt_without_signature_verification",
            return_value=fake_token_obj,
        ),
        patch(
            "supertokens_python.recipe.oauth2provider.recipe_implementation.get_latest_keys",
            return_value=[],
        ),
    ):
        with raises(Exception, match="No JWKS key matching kid"):
            await OAuth2ProviderRecipe.get_instance().recipe_implementation.validate_oauth2_access_token(
                token="some-jwt",
                requirements=None,
                check_database=False,
                user_context={},
            )


@min_api_version("2.14")
async def test_validate_access_token_uses_algorithm_from_jwk():
    """When the matching JWK declares algorithm_name='ES256', jwt.decode must
    be called with algorithms=['ES256'], not the previously-hardcoded
    ['RS256']. The fallback to 'RS256' is preserved when the JWK doesn't
    declare an algorithm."""
    _init_recipe()

    fake_token_obj = MagicMock()
    fake_token_obj.kid = "es-kid"

    fake_key = MagicMock()
    fake_key.algorithm_name = "ES256"
    fake_key.key = "fake-key-material"

    captured_algorithms: List[Optional[List[str]]] = []

    def fake_decode(
        *_args: Any, algorithms: Optional[List[str]] = None, **_kwargs: Any
    ) -> Dict[str, Any]:
        captured_algorithms.append(algorithms)
        return {"stt": 1, "tId": "public", "sessionHandle": "handle-1"}

    with (
        patch(
            "supertokens_python.recipe.oauth2provider.recipe_implementation.parse_jwt_without_signature_verification",
            return_value=fake_token_obj,
        ),
        patch(
            "supertokens_python.recipe.oauth2provider.recipe_implementation.get_latest_keys",
            return_value=[fake_key],
        ),
        patch(
            "supertokens_python.recipe.oauth2provider.recipe_implementation.jwt.decode",
            side_effect=fake_decode,
        ),
    ):
        await OAuth2ProviderRecipe.get_instance().recipe_implementation.validate_oauth2_access_token(
            token="some-jwt",
            requirements=None,
            check_database=False,
            user_context={},
        )

    assert captured_algorithms == [["ES256"]]


@min_api_version("2.14")
async def test_validate_access_token_falls_back_to_rs256_when_jwk_has_no_algorithm():
    _init_recipe()

    fake_token_obj = MagicMock()
    fake_token_obj.kid = "no-alg-kid"

    fake_key = MagicMock()
    fake_key.algorithm_name = None
    fake_key.key = "fake-key-material"

    captured_algorithms: List[Optional[List[str]]] = []

    def fake_decode(
        *_args: Any, algorithms: Optional[List[str]] = None, **_kwargs: Any
    ) -> Dict[str, Any]:
        captured_algorithms.append(algorithms)
        return {"stt": 1}

    with (
        patch(
            "supertokens_python.recipe.oauth2provider.recipe_implementation.parse_jwt_without_signature_verification",
            return_value=fake_token_obj,
        ),
        patch(
            "supertokens_python.recipe.oauth2provider.recipe_implementation.get_latest_keys",
            return_value=[fake_key],
        ),
        patch(
            "supertokens_python.recipe.oauth2provider.recipe_implementation.jwt.decode",
            side_effect=fake_decode,
        ),
    ):
        await OAuth2ProviderRecipe.get_instance().recipe_implementation.validate_oauth2_access_token(
            token="some-jwt",
            requirements=None,
            check_database=False,
            user_context={},
        )

    assert captured_algorithms == [["RS256"]]


@min_api_version("2.14")
async def test_oauth2provider_reset_clears_session_jwks_cache():
    """reset() on the OAuth2 provider recipe must also drop the session
    recipe's JWKS cache, so a fresh recipe instance against a new core
    doesn't reuse stale keys from a previous one."""
    import os

    os.environ["SUPERTOKENS_ENV"] = "testing"
    _init_recipe()

    with patch(
        "supertokens_python.recipe.session.jwks.reset_jwks_cache"
    ) as mocked_reset:
        OAuth2ProviderRecipe.reset()

    mocked_reset.assert_called_once()
