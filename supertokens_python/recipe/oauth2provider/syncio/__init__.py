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

from ..interfaces import (
    ActiveTokenResponse,
    CreatedOAuth2ClientResponse,
    CreateOAuth2ClientInput,
    DeleteOAuth2ClientOkResponse,
    ErrorOAuth2Response,
    InactiveTokenResponse,
    OAuth2ClientResponse,
    OAuth2ClientsListResponse,
    OAuth2TokenValidationRequirements,
    RevokeTokenOkResponse,
    TokenInfoResponse,
    UpdatedOAuth2ClientResponse,
    UpdateOAuth2ClientInput,
    ValidatedAccessTokenResponse,
)


def get_oauth2_client(
    client_id: str, user_context: Optional[Dict[str, Any]] = None
) -> Union[OAuth2ClientResponse, ErrorOAuth2Response]:
    if user_context is None:
        user_context = {}

    from ..asyncio import get_oauth2_client

    return sync(get_oauth2_client(client_id, user_context))


def get_oauth2_clients(
    page_size: Optional[int] = None,
    pagination_token: Optional[str] = None,
    client_name: Optional[str] = None,
    user_context: Optional[Dict[str, Any]] = None,
) -> Union[OAuth2ClientsListResponse, ErrorOAuth2Response]:
    if user_context is None:
        user_context = {}

    from ..asyncio import get_oauth2_clients

    return sync(
        get_oauth2_clients(page_size, pagination_token, client_name, user_context)
    )


def create_oauth2_client(
    params: CreateOAuth2ClientInput,
    user_context: Optional[Dict[str, Any]] = None,
) -> Union[CreatedOAuth2ClientResponse, ErrorOAuth2Response]:
    if user_context is None:
        user_context = {}
    from ..asyncio import create_oauth2_client

    return sync(create_oauth2_client(params, user_context))


def update_oauth2_client(
    params: UpdateOAuth2ClientInput,
    user_context: Optional[Dict[str, Any]] = None,
) -> Union[UpdatedOAuth2ClientResponse, ErrorOAuth2Response]:
    if user_context is None:
        user_context = {}

    from ..asyncio import update_oauth2_client

    return sync(update_oauth2_client(params, user_context))


def delete_oauth2_client(
    client_id: str, user_context: Optional[Dict[str, Any]] = None
) -> Union[DeleteOAuth2ClientOkResponse, ErrorOAuth2Response]:
    if user_context is None:
        user_context = {}
    from ..asyncio import delete_oauth2_client

    return sync(delete_oauth2_client(client_id, user_context))


def validate_oauth2_access_token(
    token: str,
    requirements: Optional[OAuth2TokenValidationRequirements] = None,
    check_database: Optional[bool] = None,
    user_context: Optional[Dict[str, Any]] = None,
) -> ValidatedAccessTokenResponse:
    if user_context is None:
        user_context = {}

    from ..asyncio import validate_oauth2_access_token

    return sync(
        validate_oauth2_access_token(token, requirements, check_database, user_context)
    )


def create_token_for_client_credentials(
    client_id: str,
    client_secret: str,
    scope: Optional[List[str]] = None,
    audience: Optional[str] = None,
    user_context: Optional[Dict[str, Any]] = None,
) -> Union[TokenInfoResponse, ErrorOAuth2Response]:
    if user_context is None:
        user_context = {}

    from ..asyncio import create_token_for_client_credentials

    return sync(
        create_token_for_client_credentials(
            client_id, client_secret, scope, audience, user_context
        )
    )


def revoke_token(
    token: str,
    client_id: str,
    client_secret: Optional[str] = None,
    user_context: Optional[Dict[str, Any]] = None,
) -> Union[RevokeTokenOkResponse, ErrorOAuth2Response]:
    if user_context is None:
        user_context = {}
    from ..asyncio import revoke_token

    return sync(revoke_token(token, client_id, client_secret, user_context))


def revoke_tokens_by_client_id(
    client_id: str, user_context: Optional[Dict[str, Any]] = None
) -> None:
    if user_context is None:
        user_context = {}

    from ..asyncio import revoke_tokens_by_client_id

    return sync(revoke_tokens_by_client_id(client_id, user_context))


def revoke_tokens_by_session_handle(
    session_handle: str, user_context: Optional[Dict[str, Any]] = None
) -> None:
    if user_context is None:
        user_context = {}

    from ..asyncio import revoke_tokens_by_session_handle

    return sync(revoke_tokens_by_session_handle(session_handle, user_context))


def validate_oauth2_refresh_token(
    token: str,
    scopes: Optional[List[str]] = None,
    user_context: Optional[Dict[str, Any]] = None,
) -> Union[ActiveTokenResponse, InactiveTokenResponse]:
    if user_context is None:
        user_context = {}

    from ..asyncio import validate_oauth2_refresh_token

    return sync(validate_oauth2_refresh_token(token, scopes, user_context))
