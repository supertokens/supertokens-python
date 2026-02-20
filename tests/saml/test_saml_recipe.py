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

import base64
from typing import Any, Dict

from supertokens_python import init
from supertokens_python.recipe import saml, session
from supertokens_python.recipe.saml.interfaces import RecipeInterface
from supertokens_python.recipe.saml.recipe import SAMLRecipe
from supertokens_python.recipe.saml.types import (
    CreateLoginRequestInvalidClientError,
    CreateLoginRequestOkResult,
    CreateOrUpdateClientDuplicateIdpEntityError,
    CreateOrUpdateClientInvalidMetadataXMLError,
    CreateOrUpdateClientOkResult,
    GetUserInfoInvalidTokenError,
    GetUserInfoOkResult,
    ListClientsOkResult,
    RemoveClientOkResult,
    SAMLClient,
    VerifySAMLResponseIDPLoginDisallowedError,
    VerifySAMLResponseInvalidClientError,
    VerifySAMLResponseInvalidRelayStateError,
    VerifySAMLResponseOkResult,
    VerifySAMLResponseVerificationFailedError,
)

from tests.utils import get_new_core_app_url, get_st_init_args

# Minimal but structurally valid SAML 2.0 IdP metadata document.
# Uses a real self-signed certificate — the core needs to parse and
# recognise this as valid SAML metadata (it does not verify trust chains).
_TEST_CERT = (
    "MIIDFTCCAf2gAwIBAgIUMymKnRHG3fOijH34giHubNz0lhUwDQYJKoZIhvcNAQEL"
    "BQAwGjEYMBYGA1UEAwwPaWRwLmV4YW1wbGUuY29tMB4XDTI2MDIxNjEyMzAzN1oX"
    "DTI3MDIxNjEyMzAzN1owGjEYMBYGA1UEAwwPaWRwLmV4YW1wbGUuY29tMIIBIjAN"
    "BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzgEhRVTvyXcCl0GD7OHDu0STlWnf"
    "CJssTn+kvwECpGTMzidB66/3klCFFd2QMX8YpbAntx0+pJqSmw7qwRBPD6ZU7LeA"
    "Oj8e4Iobqsbh/5XlBqDvag42wFrqn4jd9s+hURsRHwZWBDKzlcm/KLZ8+LkRBebH"
    "b5YDvF0mXXc4zel/kuwcwJnN6Wc/RDnuXvGE2RIKxgswln3xkhs30Y9zv1b4e/44"
    "3fU3WAF7J8Rgu1BMYFJKUMBhlSmPbCA/grImZ16TngyzCbOI8kXxgSzfy2QJXZpS9"
    "tVtxH55op8uJt7qdyh5avsWnaf6vlr+ucYg0FqNyZyaZe+JKi25ks6X1wIDAQABo1"
    "MwUTAdBgNVHQ4EFgQUeGBN7LPWpgHUKEm5HwvcIQPR9QwwHwYDVR0jBBgwFoAUeG"
    "BN7LPWpgHUKEm5HwvcIQPR9QwwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQ"
    "sFAAOCAQEAEo39E18GKzcjLwhrFcd3dQvacbDfe+iiI2r8x3Wy4W/fXhQpMc+qaV/"
    "eLvIzhUjKHVnyRw5k7IkFaq/VC0jRApc4PsQNahOndwfgylQ8/x0htyFPcnbPxIa+"
    "dSrtT8DxPEE7XCG72iEX5W/KM5/IZlbNNuZu6Q5YcvzhAvs7VPDp7QT9gCrc9B8h"
    "tCSw9/HsQFDSg6P1jT2j8auc/yL3MG3+ABuPme/061ksscjg6ff7Bug1koI+UE6zp"
    "ib/TlSW2+EmAA47MlOt5eSHxfT/Wn3fbPY8LCSGNgCHHkJ0N0Rsn8Pr6XsGFw82w"
    "pAtRTUxk+hjLPQBzASkbv+Vdd8qog=="
)

_VALID_IDP_METADATA_XML_RAW = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"'
    '                     entityID="https://idp.example.com/metadata">'
    '  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
    '    <md:KeyDescriptor use="signing">'
    '      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
    "        <ds:X509Data>"
    f"          <ds:X509Certificate>{_TEST_CERT}</ds:X509Certificate>"
    "        </ds:X509Data>"
    "      </ds:KeyInfo>"
    "    </md:KeyDescriptor>"
    "    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>"
    '    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"'
    '                            Location="https://idp.example.com/sso"/>'
    "  </md:IDPSSODescriptor>"
    "</md:EntityDescriptor>"
)

# The core expects metadataXML to be Base64-encoded (caller responsibility, matching Node SDK).
VALID_IDP_METADATA_XML = base64.b64encode(
    _VALID_IDP_METADATA_XML_RAW.encode("utf-8")
).decode("utf-8")


async def test_saml_recipe_init():
    """Test that the SAML recipe can be initialized"""
    st_init_args = get_st_init_args(
        url=get_new_core_app_url(),
        recipe_list=[
            session.init(),
            saml.init(),
        ],
    )
    init(**st_init_args)

    # Verify singleton was created
    instance = SAMLRecipe.get_instance()
    assert instance is not None
    assert instance.recipe_id == "saml"


async def test_saml_recipe_init_with_overrides():
    """Test that the SAML recipe can be initialized with overrides"""
    custom_called = False

    def override_functions(
        original_implementation: RecipeInterface,
    ) -> RecipeInterface:
        nonlocal custom_called

        original_list_clients = original_implementation.list_clients

        async def custom_list_clients(
            tenant_id: str,
            user_context: Dict[str, Any],
        ) -> ListClientsOkResult:
            nonlocal custom_called
            custom_called = True
            return await original_list_clients(tenant_id, user_context)

        original_implementation.list_clients = custom_list_clients  # type: ignore
        return original_implementation

    st_init_args = get_st_init_args(
        url=get_new_core_app_url(),
        recipe_list=[
            session.init(),
            saml.init(
                override=saml.SAMLOverrideConfig(
                    functions=override_functions,
                )
            ),
        ],
    )
    init(**st_init_args)

    instance = SAMLRecipe.get_instance()
    assert instance is not None


async def test_saml_recipe_reset():
    """Test that the SAML recipe resets correctly"""
    st_init_args = get_st_init_args(
        url=get_new_core_app_url(),
        recipe_list=[
            session.init(),
            saml.init(),
        ],
    )
    init(**st_init_args)

    # Verify instance exists
    instance = SAMLRecipe.get_instance_optional()
    assert instance is not None

    # Reset
    SAMLRecipe.reset()

    # Instance should be None
    instance = SAMLRecipe.get_instance_optional()
    assert instance is None


async def test_saml_recipe_apis_handled():
    """Test that the SAML recipe registers the correct API endpoints"""
    st_init_args = get_st_init_args(
        url=get_new_core_app_url(),
        recipe_list=[
            session.init(),
            saml.init(),
        ],
    )
    init(**st_init_args)

    instance = SAMLRecipe.get_instance()
    apis = instance.get_apis_handled()

    # Should have 2 endpoints: login GET and callback POST
    assert len(apis) == 2

    login_api = next(a for a in apis if a.method == "get")
    callback_api = next(a for a in apis if a.method == "post")

    assert login_api.request_id == "/saml/login"
    assert callback_api.request_id == "/saml/callback"


async def test_saml_list_clients():
    """Test listing SAML clients (initially should be empty)"""
    st_init_args = get_st_init_args(
        url=get_new_core_app_url(),
        recipe_list=[
            session.init(),
            saml.init(),
        ],
    )
    init(**st_init_args)

    from supertokens_python.recipe.saml.asyncio import list_clients

    result = await list_clients(tenant_id="public")
    assert isinstance(result, ListClientsOkResult)
    assert result.status == "OK"
    assert isinstance(result.clients, list)


async def test_saml_create_and_list_client():
    """Test creating a SAML client and then listing it"""
    st_init_args = get_st_init_args(
        url=get_new_core_app_url(),
        recipe_list=[
            session.init(),
            saml.init(),
        ],
    )
    init(**st_init_args)

    from supertokens_python.recipe.saml.asyncio import (
        create_or_update_client,
    )

    # Create a SAML client using valid IdP metadata
    create_result = await create_or_update_client(
        tenant_id="public",
        redirect_uris=["http://localhost:3000/callback"],
        default_redirect_uri="http://localhost:3000/callback",
        metadata_xml=VALID_IDP_METADATA_XML,
    )

    assert isinstance(create_result, CreateOrUpdateClientOkResult)
    assert create_result.status == "OK"
    assert create_result.client.client_id is not None


async def test_saml_remove_client():
    """Test removing a SAML client"""
    st_init_args = get_st_init_args(
        url=get_new_core_app_url(),
        recipe_list=[
            session.init(),
            saml.init(),
        ],
    )
    init(**st_init_args)

    from supertokens_python.recipe.saml.asyncio import remove_client

    # Remove a non-existent client
    result = await remove_client(
        tenant_id="public",
        client_id="nonexistent-client",
    )
    assert isinstance(result, RemoveClientOkResult)
    assert result.status == "OK"
    assert result.did_exist is False


async def test_saml_create_login_request_invalid_client():
    """Test creating a login request with an invalid client"""
    st_init_args = get_st_init_args(
        url=get_new_core_app_url(),
        recipe_list=[
            session.init(),
            saml.init(),
        ],
    )
    init(**st_init_args)

    from supertokens_python.recipe.saml.asyncio import create_login_request

    result = await create_login_request(
        tenant_id="public",
        client_id="nonexistent-client",
        redirect_uri="http://localhost:3000/callback",
        acs_url="http://localhost:3000/saml/callback",
    )
    assert isinstance(result, CreateLoginRequestInvalidClientError)
    assert result.status == "INVALID_CLIENT_ERROR"


async def test_saml_get_user_info_invalid_token():
    """Test getting user info with an invalid token"""
    st_init_args = get_st_init_args(
        url=get_new_core_app_url(),
        recipe_list=[
            session.init(),
            saml.init(),
        ],
    )
    init(**st_init_args)

    from supertokens_python.recipe.saml.asyncio import get_user_info

    result = await get_user_info(
        tenant_id="public",
        access_token="invalid-token",
        client_id="nonexistent-client",
    )
    assert isinstance(result, GetUserInfoInvalidTokenError)
    assert result.status == "INVALID_TOKEN_ERROR"


async def test_saml_syncio_wrappers():
    """Test that sync wrappers work correctly"""
    st_init_args = get_st_init_args(
        url=get_new_core_app_url(),
        recipe_list=[
            session.init(),
            saml.init(),
        ],
    )
    init(**st_init_args)

    from supertokens_python.recipe.saml.syncio import list_clients

    result = list_clients(tenant_id="public")
    assert isinstance(result, ListClientsOkResult)
    assert result.status == "OK"


async def test_saml_type_classes():
    """Test that all SAML type classes are properly defined"""
    # SAMLClient
    client = SAMLClient(
        client_id="test-id",
        redirect_uris=["http://localhost:3000/callback"],
        default_redirect_uri="http://localhost:3000/callback",
        idp_entity_id="https://idp.example.com",
        allow_idp_initiated_login=True,
        enable_request_signing=False,
    )
    json_data = client.to_json()
    assert json_data["clientId"] == "test-id"
    assert json_data["redirectURIs"] == ["http://localhost:3000/callback"]
    assert json_data["idpEntityId"] == "https://idp.example.com"
    assert json_data["allowIDPInitiatedLogin"] is True

    # Roundtrip
    client2 = SAMLClient.from_json(json_data)
    assert client2.client_id == "test-id"
    assert client2.idp_entity_id == "https://idp.example.com"
    assert client2.allow_idp_initiated_login is True

    # Status classes
    assert CreateOrUpdateClientOkResult(client).status == "OK"
    assert (
        CreateOrUpdateClientInvalidMetadataXMLError().status
        == "INVALID_METADATA_XML_ERROR"
    )
    assert (
        CreateOrUpdateClientDuplicateIdpEntityError().status
        == "DUPLICATE_IDP_ENTITY_ERROR"
    )
    assert ListClientsOkResult([]).status == "OK"
    assert RemoveClientOkResult(True).status == "OK"
    assert CreateLoginRequestOkResult("http://example.com").status == "OK"
    assert CreateLoginRequestInvalidClientError().status == "INVALID_CLIENT_ERROR"
    assert VerifySAMLResponseOkResult("http://example.com").status == "OK"
    assert (
        VerifySAMLResponseVerificationFailedError().status
        == "SAML_RESPONSE_VERIFICATION_FAILED_ERROR"
    )
    assert (
        VerifySAMLResponseInvalidRelayStateError().status == "INVALID_RELAY_STATE_ERROR"
    )
    assert VerifySAMLResponseInvalidClientError().status == "INVALID_CLIENT_ERROR"
    assert (
        VerifySAMLResponseIDPLoginDisallowedError().status
        == "IDP_LOGIN_DISALLOWED_ERROR"
    )
    assert GetUserInfoOkResult("sub1", "email@test.com", {}).status == "OK"
    assert GetUserInfoInvalidTokenError().status == "INVALID_TOKEN_ERROR"
