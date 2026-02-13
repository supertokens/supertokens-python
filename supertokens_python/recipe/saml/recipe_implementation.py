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
from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List, Optional, Union

from supertokens_python.normalised_url_path import NormalisedURLPath

from .interfaces import RecipeInterface
from .types import (
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

if TYPE_CHECKING:
    from supertokens_python.querier import Querier


class RecipeImplementation(RecipeInterface):
    def __init__(self, querier: Querier):
        super().__init__()
        self.querier = querier

    async def create_or_update_client(
        self,
        tenant_id: str,
        redirect_uris: List[str],
        default_redirect_uri: str,
        metadata_xml: str,
        client_id: Optional[str],
        client_secret: Optional[str],
        allow_idp_initiated_login: Optional[bool],
        enable_request_signing: Optional[bool],
        user_context: Dict[str, Any],
    ) -> Union[
        CreateOrUpdateClientOkResult,
        CreateOrUpdateClientInvalidMetadataXMLError,
        CreateOrUpdateClientDuplicateIdpEntityError,
    ]:
        body: Dict[str, Any] = {
            "redirectURIs": redirect_uris,
            "defaultRedirectURI": default_redirect_uri,
            "metadataXML": metadata_xml,
        }
        if client_id is not None:
            body["clientId"] = client_id
        if client_secret is not None:
            body["clientSecret"] = client_secret
        if allow_idp_initiated_login is not None:
            body["allowIDPInitiatedLogin"] = allow_idp_initiated_login
        if enable_request_signing is not None:
            body["enableRequestSigning"] = enable_request_signing

        response = await self.querier.send_put_request(
            NormalisedURLPath(f"{tenant_id}/recipe/saml/clients"),
            body,
            None,
            user_context=user_context,
        )

        if response["status"] == "OK":
            return CreateOrUpdateClientOkResult(client=SAMLClient.from_json(response))
        elif response["status"] == "INVALID_METADATA_XML_ERROR":
            return CreateOrUpdateClientInvalidMetadataXMLError()
        else:
            return CreateOrUpdateClientDuplicateIdpEntityError()

    async def list_clients(
        self,
        tenant_id: str,
        user_context: Dict[str, Any],
    ) -> ListClientsOkResult:
        response = await self.querier.send_get_request(
            NormalisedURLPath(f"{tenant_id}/recipe/saml/clients/list"),
            {},
            user_context=user_context,
        )

        clients = [SAMLClient.from_json(c) for c in response.get("clients", [])]
        return ListClientsOkResult(clients=clients)

    async def remove_client(
        self,
        tenant_id: str,
        client_id: str,
        user_context: Dict[str, Any],
    ) -> RemoveClientOkResult:
        response = await self.querier.send_post_request(
            NormalisedURLPath(f"{tenant_id}/recipe/saml/clients/remove"),
            {"clientId": client_id},
            user_context=user_context,
        )

        return RemoveClientOkResult(did_exist=response.get("didExist", False))

    async def create_login_request(
        self,
        tenant_id: str,
        client_id: str,
        redirect_uri: str,
        acs_url: str,
        state: Optional[str],
        user_context: Dict[str, Any],
    ) -> Union[
        CreateLoginRequestOkResult,
        CreateLoginRequestInvalidClientError,
    ]:
        body: Dict[str, Any] = {
            "clientId": client_id,
            "redirectURI": redirect_uri,
            "acsURL": acs_url,
        }
        if state is not None:
            body["state"] = state

        response = await self.querier.send_post_request(
            NormalisedURLPath(f"{tenant_id}/recipe/saml/login"),
            body,
            user_context=user_context,
        )

        if response["status"] == "OK":
            return CreateLoginRequestOkResult(redirect_uri=response["ssoRedirectURI"])
        else:
            return CreateLoginRequestInvalidClientError()

    async def verify_saml_response(
        self,
        tenant_id: str,
        saml_response: str,
        relay_state: Optional[str],
        user_context: Dict[str, Any],
    ) -> Union[
        VerifySAMLResponseOkResult,
        VerifySAMLResponseVerificationFailedError,
        VerifySAMLResponseInvalidRelayStateError,
        VerifySAMLResponseInvalidClientError,
        VerifySAMLResponseIDPLoginDisallowedError,
    ]:
        body: Dict[str, Any] = {
            "samlResponse": saml_response,
        }
        if relay_state is not None:
            body["relayState"] = relay_state

        response = await self.querier.send_post_request(
            NormalisedURLPath(f"{tenant_id}/recipe/saml/callback"),
            body,
            user_context=user_context,
        )

        status = response["status"]
        if status == "OK":
            return VerifySAMLResponseOkResult(redirect_uri=response["redirectURI"])
        elif status == "SAML_RESPONSE_VERIFICATION_FAILED_ERROR":
            return VerifySAMLResponseVerificationFailedError()
        elif status == "INVALID_RELAY_STATE_ERROR":
            return VerifySAMLResponseInvalidRelayStateError()
        elif status == "INVALID_CLIENT_ERROR":
            return VerifySAMLResponseInvalidClientError()
        else:
            return VerifySAMLResponseIDPLoginDisallowedError()

    async def get_user_info(
        self,
        tenant_id: str,
        access_token: str,
        client_id: str,
        user_context: Dict[str, Any],
    ) -> Union[
        GetUserInfoOkResult,
        GetUserInfoInvalidTokenError,
    ]:
        response = await self.querier.send_post_request(
            NormalisedURLPath(f"{tenant_id}/recipe/saml/user"),
            {
                "accessToken": access_token,
                "clientId": client_id,
            },
            user_context=user_context,
        )

        if response["status"] == "OK":
            return GetUserInfoOkResult(
                sub=response["sub"],
                email=response["email"],
                claims=response.get("claims", {}),
            )
        else:
            return GetUserInfoInvalidTokenError()
