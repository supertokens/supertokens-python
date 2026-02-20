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

from typing import Any, Dict, List, Optional, Union

from supertokens_python.async_to_sync_wrapper import sync

from ..types import (
    CreateLoginRequestInvalidClientError,
    CreateLoginRequestOkResult,
    CreateOrUpdateClientDuplicateIdpEntityError,
    CreateOrUpdateClientInvalidMetadataXMLError,
    CreateOrUpdateClientOkResult,
    GetUserInfoInvalidTokenError,
    GetUserInfoOkResult,
    ListClientsOkResult,
    RemoveClientOkResult,
    VerifySAMLResponseIDPLoginDisallowedError,
    VerifySAMLResponseInvalidClientError,
    VerifySAMLResponseInvalidRelayStateError,
    VerifySAMLResponseOkResult,
    VerifySAMLResponseVerificationFailedError,
)


def create_or_update_client(
    tenant_id: str,
    redirect_uris: List[str],
    default_redirect_uri: str,
    metadata_xml: str,
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
    allow_idp_initiated_login: Optional[bool] = None,
    enable_request_signing: Optional[bool] = None,
    user_context: Optional[Dict[str, Any]] = None,
) -> Union[
    CreateOrUpdateClientOkResult,
    CreateOrUpdateClientInvalidMetadataXMLError,
    CreateOrUpdateClientDuplicateIdpEntityError,
]:
    if user_context is None:
        user_context = {}

    from ..asyncio import create_or_update_client

    return sync(
        create_or_update_client(
            tenant_id,
            redirect_uris,
            default_redirect_uri,
            metadata_xml,
            client_id,
            client_secret,
            allow_idp_initiated_login,
            enable_request_signing,
            user_context,
        )
    )


def list_clients(
    tenant_id: str,
    user_context: Optional[Dict[str, Any]] = None,
) -> ListClientsOkResult:
    if user_context is None:
        user_context = {}

    from ..asyncio import list_clients

    return sync(list_clients(tenant_id, user_context))


def remove_client(
    tenant_id: str,
    client_id: str,
    user_context: Optional[Dict[str, Any]] = None,
) -> RemoveClientOkResult:
    if user_context is None:
        user_context = {}

    from ..asyncio import remove_client

    return sync(remove_client(tenant_id, client_id, user_context))


def create_login_request(
    tenant_id: str,
    client_id: str,
    redirect_uri: str,
    acs_url: str,
    state: Optional[str] = None,
    user_context: Optional[Dict[str, Any]] = None,
) -> Union[
    CreateLoginRequestOkResult,
    CreateLoginRequestInvalidClientError,
]:
    if user_context is None:
        user_context = {}

    from ..asyncio import create_login_request

    return sync(
        create_login_request(
            tenant_id, client_id, redirect_uri, acs_url, state, user_context
        )
    )


def verify_saml_response(
    tenant_id: str,
    saml_response: str,
    relay_state: Optional[str] = None,
    user_context: Optional[Dict[str, Any]] = None,
) -> Union[
    VerifySAMLResponseOkResult,
    VerifySAMLResponseVerificationFailedError,
    VerifySAMLResponseInvalidRelayStateError,
    VerifySAMLResponseInvalidClientError,
    VerifySAMLResponseIDPLoginDisallowedError,
]:
    if user_context is None:
        user_context = {}

    from ..asyncio import verify_saml_response

    return sync(
        verify_saml_response(tenant_id, saml_response, relay_state, user_context)
    )


def get_user_info(
    tenant_id: str,
    access_token: str,
    client_id: str,
    user_context: Optional[Dict[str, Any]] = None,
) -> Union[
    GetUserInfoOkResult,
    GetUserInfoInvalidTokenError,
]:
    if user_context is None:
        user_context = {}

    from ..asyncio import get_user_info

    return sync(get_user_info(tenant_id, access_token, client_id, user_context))
