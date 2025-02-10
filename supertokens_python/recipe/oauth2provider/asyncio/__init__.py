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

import base64
from typing import Any, Dict, List, Optional, Union

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
    RevokeTokenUsingAuthorizationHeader,
    RevokeTokenUsingClientIDAndClientSecret,
    TokenInfoResponse,
    UpdatedOAuth2ClientResponse,
    UpdateOAuth2ClientInput,
    ValidatedAccessTokenResponse,
)


async def get_oauth2_client(
    client_id: str, user_context: Optional[Dict[str, Any]] = None
) -> Union[OAuth2ClientResponse, ErrorOAuth2Response]:
    if user_context is None:
        user_context = {}
    from ..recipe import OAuth2ProviderRecipe

    return await OAuth2ProviderRecipe.get_instance().recipe_implementation.get_oauth2_client(
        client_id=client_id, user_context=user_context
    )


async def get_oauth2_clients(
    page_size: Optional[int] = None,
    pagination_token: Optional[str] = None,
    client_name: Optional[str] = None,
    user_context: Optional[Dict[str, Any]] = None,
) -> Union[OAuth2ClientsListResponse, ErrorOAuth2Response]:
    if user_context is None:
        user_context = {}
    from ..recipe import OAuth2ProviderRecipe

    return await OAuth2ProviderRecipe.get_instance().recipe_implementation.get_oauth2_clients(
        page_size=page_size,
        pagination_token=pagination_token,
        client_name=client_name,
        user_context=user_context,
    )


async def create_oauth2_client(
    params: CreateOAuth2ClientInput,
    user_context: Optional[Dict[str, Any]] = None,
) -> Union[CreatedOAuth2ClientResponse, ErrorOAuth2Response]:
    if user_context is None:
        user_context = {}
    from ..recipe import OAuth2ProviderRecipe

    return await OAuth2ProviderRecipe.get_instance().recipe_implementation.create_oauth2_client(
        params=params,
        user_context=user_context,
    )


async def update_oauth2_client(
    params: UpdateOAuth2ClientInput,
    user_context: Optional[Dict[str, Any]] = None,
) -> Union[UpdatedOAuth2ClientResponse, ErrorOAuth2Response]:
    if user_context is None:
        user_context = {}
    from ..recipe import OAuth2ProviderRecipe

    return await OAuth2ProviderRecipe.get_instance().recipe_implementation.update_oauth2_client(
        params=params,
        user_context=user_context,
    )


async def delete_oauth2_client(
    client_id: str, user_context: Optional[Dict[str, Any]] = None
) -> Union[DeleteOAuth2ClientOkResponse, ErrorOAuth2Response]:
    if user_context is None:
        user_context = {}
    from ..recipe import OAuth2ProviderRecipe

    return await OAuth2ProviderRecipe.get_instance().recipe_implementation.delete_oauth2_client(
        client_id=client_id, user_context=user_context
    )


async def validate_oauth2_access_token(
    token: str,
    requirements: Optional[OAuth2TokenValidationRequirements] = None,
    check_database: Optional[bool] = None,
    user_context: Optional[Dict[str, Any]] = None,
) -> ValidatedAccessTokenResponse:
    if user_context is None:
        user_context = {}
    from ..recipe import OAuth2ProviderRecipe

    return await OAuth2ProviderRecipe.get_instance().recipe_implementation.validate_oauth2_access_token(
        token=token,
        requirements=requirements,
        check_database=check_database,
        user_context=user_context,
    )


async def create_token_for_client_credentials(
    client_id: str,
    client_secret: Optional[str] = None,
    scope: Optional[List[str]] = None,
    audience: Optional[str] = None,
    user_context: Optional[Dict[str, Any]] = None,
) -> Union[TokenInfoResponse, ErrorOAuth2Response]:
    if user_context is None:
        user_context = {}
    from ..recipe import OAuth2ProviderRecipe

    body: Dict[str, Any] = {
        "grant_type": "client_credentials",
        "client_id": client_id,
    }
    if client_secret:
        body["client_secret"] = client_secret
    if scope:
        body["scope"] = " ".join(scope)
    if audience:
        body["audience"] = audience

    return (
        await OAuth2ProviderRecipe.get_instance().recipe_implementation.token_exchange(
            authorization_header=None,
            body=body,
            user_context=user_context,
        )
    )


async def revoke_token(
    token: str,
    client_id: str,
    client_secret: Optional[str] = None,
    user_context: Optional[Dict[str, Any]] = None,
) -> Union[RevokeTokenOkResponse, ErrorOAuth2Response]:
    if user_context is None:
        user_context = {}
    from ..recipe import OAuth2ProviderRecipe

    recipe = OAuth2ProviderRecipe.get_instance()

    client_info = await recipe.recipe_implementation.get_oauth2_client(
        client_id=client_id, user_context=user_context
    )

    if isinstance(client_info, ErrorOAuth2Response):
        raise Exception(
            f"Failed to get OAuth2 client with id {client_id}: {client_info.error}"
        )

    token_endpoint_auth_method = client_info.client.token_endpoint_auth_method

    if token_endpoint_auth_method == "none":
        auth_header = "Basic " + base64.b64encode(f"{client_id}:".encode()).decode()
        return await recipe.recipe_implementation.revoke_token(
            RevokeTokenUsingAuthorizationHeader(
                token=token,
                authorization_header=auth_header,
            ),
            user_context=user_context,
        )
    elif token_endpoint_auth_method == "client_secret_basic" and client_secret:
        auth_header = (
            "Basic "
            + base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
        )
        return await recipe.recipe_implementation.revoke_token(
            RevokeTokenUsingAuthorizationHeader(
                token=token,
                authorization_header=auth_header,
            ),
            user_context=user_context,
        )

    return await recipe.recipe_implementation.revoke_token(
        RevokeTokenUsingClientIDAndClientSecret(
            token=token,
            client_id=client_id,
            client_secret=client_secret,
        ),
        user_context=user_context,
    )


async def revoke_tokens_by_client_id(
    client_id: str, user_context: Optional[Dict[str, Any]] = None
) -> None:
    if user_context is None:
        user_context = {}
    from ..recipe import OAuth2ProviderRecipe

    return await OAuth2ProviderRecipe.get_instance().recipe_implementation.revoke_tokens_by_client_id(
        client_id=client_id, user_context=user_context
    )


async def revoke_tokens_by_session_handle(
    session_handle: str, user_context: Optional[Dict[str, Any]] = None
) -> None:
    if user_context is None:
        user_context = {}
    from ..recipe import OAuth2ProviderRecipe

    return await OAuth2ProviderRecipe.get_instance().recipe_implementation.revoke_tokens_by_session_handle(
        session_handle=session_handle, user_context=user_context
    )


async def validate_oauth2_refresh_token(
    token: str,
    scopes: Optional[List[str]] = None,
    user_context: Optional[Dict[str, Any]] = None,
) -> Union[ActiveTokenResponse, InactiveTokenResponse]:
    if user_context is None:
        user_context = {}
    from ..recipe import OAuth2ProviderRecipe

    return await OAuth2ProviderRecipe.get_instance().recipe_implementation.introspect_token(
        token=token, scopes=scopes, user_context=user_context
    )
