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

from typing import Any, Dict, Optional, Union

from fastapi import FastAPI
from pytest import fixture
from starlette.testclient import TestClient
from supertokens_python import init
from supertokens_python.framework.fastapi import get_middleware
from supertokens_python.recipe import saml, session
from supertokens_python.recipe.saml.interfaces import (
    APIInterface,
    APIOptions,
)
from supertokens_python.recipe.saml.types import (
    CreateLoginRequestInvalidClientError,
    CreateLoginRequestOkResult,
    VerifySAMLResponseIDPLoginDisallowedError,
    VerifySAMLResponseInvalidClientError,
    VerifySAMLResponseInvalidRelayStateError,
    VerifySAMLResponseOkResult,
    VerifySAMLResponseVerificationFailedError,
)
from supertokens_python.types.response import GeneralErrorResponse

from tests.utils import get_new_core_app_url, get_st_init_args


@fixture(scope="function")
def fastapi_client():
    app = FastAPI()
    app.add_middleware(get_middleware())
    return TestClient(app, raise_server_exceptions=False)


def init_saml(override: Union[saml.SAMLOverrideConfig, None] = None):
    st_init_args = get_st_init_args(
        url=get_new_core_app_url(),
        recipe_list=[
            session.init(),
            saml.init(override=override),
        ],
    )
    init(**st_init_args)


# ──────────────────────────────────────────────────────────────
# GET /auth/saml/login — input validation
# ──────────────────────────────────────────────────────────────


async def test_login_missing_client_id(fastapi_client: TestClient):
    """Should return 400 when client_id query param is missing"""
    init_saml()
    res = fastapi_client.get(
        "/auth/saml/login?redirect_uri=http://localhost:3000/callback",
        allow_redirects=False,
    )
    assert res.status_code == 400


async def test_login_missing_redirect_uri(fastapi_client: TestClient):
    """Should return 400 when redirect_uri query param is missing"""
    init_saml()
    res = fastapi_client.get(
        "/auth/saml/login?client_id=test-client",
        allow_redirects=False,
    )
    assert res.status_code == 400


# ──────────────────────────────────────────────────────────────
# GET /auth/saml/login — invalid client (open redirect fix)
# ──────────────────────────────────────────────────────────────


async def test_login_invalid_client_returns_json_not_redirect(
    fastapi_client: TestClient,
):
    """When client_id is invalid, should return JSON error, NOT redirect
    to user-supplied redirect_uri (RFC 6749 §4.1.2.1)"""
    init_saml()
    res = fastapi_client.get(
        "/auth/saml/login?client_id=nonexistent&redirect_uri=http://evil.com/steal",
        allow_redirects=False,
    )
    # Must NOT redirect — that would be an open redirect
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "INVALID_CLIENT_ERROR"
    assert "Location" not in res.headers


# ──────────────────────────────────────────────────────────────
# GET /auth/saml/login — GeneralErrorResponse
# ──────────────────────────────────────────────────────────────


async def test_login_general_error_response(fastapi_client: TestClient):
    """Override login_get to return GeneralErrorResponse — should return
    JSON with status and message, not redirect"""

    def override_apis(original: APIInterface) -> APIInterface:
        async def custom_login_get(
            tenant_id: str,
            client_id: str,
            redirect_uri: str,
            state: Optional[str],
            options: APIOptions,
            user_context: Dict[str, Any],
        ) -> Union[
            CreateLoginRequestOkResult,
            CreateLoginRequestInvalidClientError,
            GeneralErrorResponse,
        ]:
            return GeneralErrorResponse("something went wrong")

        original.login_get = custom_login_get  # type: ignore
        return original

    init_saml(override=saml.SAMLOverrideConfig(apis=override_apis))
    res = fastapi_client.get(
        "/auth/saml/login?client_id=test&redirect_uri=http://localhost:3000",
        allow_redirects=False,
    )
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "GENERAL_ERROR"
    assert body["message"] == "something went wrong"
    assert "Location" not in res.headers


# ──────────────────────────────────────────────────────────────
# GET /auth/saml/login — disabled endpoint
# ──────────────────────────────────────────────────────────────


async def test_login_disabled(fastapi_client: TestClient):
    """When disable_login_get is True, the endpoint should return 404"""

    def override_apis(original: APIInterface) -> APIInterface:
        original.disable_login_get = True
        return original

    init_saml(override=saml.SAMLOverrideConfig(apis=override_apis))
    res = fastapi_client.get(
        "/auth/saml/login?client_id=test&redirect_uri=http://localhost:3000",
        allow_redirects=False,
    )
    assert res.status_code == 404


# ──────────────────────────────────────────────────────────────
# POST /auth/saml/callback — error responses
# ──────────────────────────────────────────────────────────────


async def test_callback_invalid_saml_response_does_not_redirect(
    fastapi_client: TestClient,
):
    """Posting an invalid SAMLResponse must not redirect — should return an
    error response. Core rejects completely invalid SAML data with a 500-level
    error (Querier raises Exception), so the status code may be 500."""
    init_saml()
    res = fastapi_client.post(
        "/auth/saml/callback",
        data={"SAMLResponse": "garbage", "RelayState": "state123"},
        allow_redirects=False,
    )
    # The important thing: no redirect to a user-supplied URI
    assert res.status_code != 302
    assert "Location" not in res.headers


async def test_callback_empty_body_does_not_redirect(fastapi_client: TestClient):
    """Posting with no body must not redirect — should return an error."""
    init_saml()
    res = fastapi_client.post(
        "/auth/saml/callback",
        allow_redirects=False,
    )
    assert res.status_code != 302
    assert "Location" not in res.headers


# ──────────────────────────────────────────────────────────────
# POST /auth/saml/callback — GeneralErrorResponse
# ──────────────────────────────────────────────────────────────


async def test_callback_general_error_response(fastapi_client: TestClient):
    """Override callback_post to return GeneralErrorResponse — should return
    JSON with status and message"""

    def override_apis(original: APIInterface) -> APIInterface:
        async def custom_callback_post(
            tenant_id: str,
            saml_response: str,
            relay_state: Optional[str],
            options: APIOptions,
            user_context: Dict[str, Any],
        ) -> Union[
            VerifySAMLResponseOkResult,
            VerifySAMLResponseVerificationFailedError,
            VerifySAMLResponseInvalidRelayStateError,
            VerifySAMLResponseInvalidClientError,
            VerifySAMLResponseIDPLoginDisallowedError,
            GeneralErrorResponse,
        ]:
            return GeneralErrorResponse("callback error")

        original.callback_post = custom_callback_post  # type: ignore
        return original

    init_saml(override=saml.SAMLOverrideConfig(apis=override_apis))
    res = fastapi_client.post(
        "/auth/saml/callback",
        data={"SAMLResponse": "test", "RelayState": "state"},
        allow_redirects=False,
    )
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "GENERAL_ERROR"
    assert body["message"] == "callback error"


# ──────────────────────────────────────────────────────────────
# POST /auth/saml/callback — disabled endpoint
# ──────────────────────────────────────────────────────────────


async def test_callback_disabled(fastapi_client: TestClient):
    """When disable_callback_post is True, the endpoint should return 404"""

    def override_apis(original: APIInterface) -> APIInterface:
        original.disable_callback_post = True
        return original

    init_saml(override=saml.SAMLOverrideConfig(apis=override_apis))
    res = fastapi_client.post(
        "/auth/saml/callback",
        data={"SAMLResponse": "test"},
        allow_redirects=False,
    )
    assert res.status_code == 404


# ──────────────────────────────────────────────────────────────
# POST /auth/saml/callback — form-encoded vs JSON body
# ──────────────────────────────────────────────────────────────


async def test_callback_json_body_does_not_redirect(fastapi_client: TestClient):
    """Callback should accept JSON body and not redirect on error."""
    init_saml()
    res = fastapi_client.post(
        "/auth/saml/callback",
        json={"SAMLResponse": "test-response", "RelayState": "state"},
        allow_redirects=False,
    )
    # Core rejects invalid SAML data, but the key assertion is no redirect
    assert res.status_code != 302
    assert "Location" not in res.headers


# ──────────────────────────────────────────────────────────────
# ThirdParty SAML provider — exchange_auth_code_for_oauth_tokens
# ──────────────────────────────────────────────────────────────


async def test_saml_provider_exchange_raises():
    """SAMLProviderImpl.exchange_auth_code_for_oauth_tokens should raise"""
    from supertokens_python.recipe.thirdparty.provider import (
        ProviderConfig,
        ProviderInput,
        RedirectUriInfo,
    )
    from supertokens_python.recipe.thirdparty.providers.saml import SAML

    init_saml()

    provider_input = ProviderInput(
        config=ProviderConfig(
            third_party_id="saml-test",
            clients=[],
        )
    )
    # SAML() returns a SAMLProviderImpl instance (which IS a Provider)
    provider = SAML(provider_input)

    redirect_uri_info = RedirectUriInfo(
        redirect_uri_on_provider_dashboard="http://localhost",
        redirect_uri_query_params={"code": "test"},
        pkce_code_verifier=None,
    )

    try:
        await provider.exchange_auth_code_for_oauth_tokens(
            redirect_uri_info=redirect_uri_info,
            user_context={},
        )
        assert False, "Should have raised"
    except Exception as e:
        assert "SAML providers do not support" in str(e)


# ──────────────────────────────────────────────────────────────
# Recipe override invocation
# ──────────────────────────────────────────────────────────────


async def test_recipe_override_is_invoked():
    """Override listClients and verify it's actually called"""
    override_called = False

    def override_functions(original):
        nonlocal override_called
        original_list = original.list_clients

        async def custom_list_clients(tenant_id, user_context):
            nonlocal override_called
            override_called = True
            return await original_list(tenant_id, user_context)

        original.list_clients = custom_list_clients  # type: ignore
        return original

    init_saml(override=saml.SAMLOverrideConfig(functions=override_functions))

    from supertokens_python.recipe.saml.asyncio import list_clients

    await list_clients(tenant_id="public")
    assert override_called is True
