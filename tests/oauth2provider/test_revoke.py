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
from unittest.mock import AsyncMock, patch

from pytest import mark
from supertokens_python import init
from supertokens_python.recipe import oauth2provider, session
from supertokens_python.recipe.oauth2provider.asyncio import (
    revoke_tokens_by_client_id,
    revoke_tokens_by_session_handle,
)

from tests.utils import (
    get_new_core_app_url,
    get_st_init_args,
    min_api_version,
)

pytestmark = mark.asyncio


@min_api_version("2.14")
async def test_revoke_tokens_by_client_id_uses_tokens_endpoint():
    """
    Regression: revoke_tokens_by_client_id must POST to
    /recipe/oauth/tokens/revoke (the client-wide revoke endpoint), not
    /recipe/oauth/session/revoke (which is the session-handle revoke endpoint
    used by revoke_tokens_by_session_handle). Sending to the wrong path
    silently no-ops on the core, leaving issued tokens valid.
    """
    init(
        **get_st_init_args(
            url=get_new_core_app_url(),
            recipe_list=[
                session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
                oauth2provider.init(),
            ],
        )
    )

    with patch(
        "supertokens_python.querier.Querier.send_post_request",
        new=AsyncMock(return_value={}),
    ) as mocked:
        await revoke_tokens_by_client_id("client-abc")

    assert mocked.await_count == 1
    call = mocked.await_args
    assert call is not None
    assert call.args[0].get_as_string_dangerous() == "/recipe/oauth/tokens/revoke"
    assert call.args[1] == {"client_id": "client-abc"}


@min_api_version("2.14")
async def test_revoke_tokens_by_session_handle_uses_session_endpoint():
    """Lock in that the session-handle path keeps using /session/revoke so
    a future fix to client-id revocation doesn't accidentally swap them."""
    init(
        **get_st_init_args(
            url=get_new_core_app_url(),
            recipe_list=[
                session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
                oauth2provider.init(),
            ],
        )
    )

    with patch(
        "supertokens_python.querier.Querier.send_post_request",
        new=AsyncMock(return_value={}),
    ) as mocked:
        await revoke_tokens_by_session_handle("handle-xyz")

    assert mocked.await_count == 1
    call = mocked.await_args
    assert call is not None
    assert call.args[0].get_as_string_dangerous() == "/recipe/oauth/session/revoke"
    assert call.args[1] == {"sessionHandle": "handle-xyz"}
