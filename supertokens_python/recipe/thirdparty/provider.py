# Copyright (c) 2021, VRAI Labs and/or its affiliates. All rights reserved.
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

from typing import TYPE_CHECKING, Any, Awaitable, Dict, Union, Optional, List, Callable

if TYPE_CHECKING:
    from .types import UserInfo


class AuthorisationRedirect:
    def __init__(
        self, url_with_query_params: str, pkce_code_verifier: Optional[str] = None
    ):
        self.url_with_query_params = url_with_query_params
        self.pkce_code_verifier = pkce_code_verifier


class RedirectUriInfo:
    def __init__(
        self,
        redirect_uri_on_provider_dashboard: str,
        redirect_uri_query_params: Dict[str, Any],
        pkce_code_verifier: Optional[str] = None,
    ):
        self.redirect_uri_on_provider_dashboard = redirect_uri_on_provider_dashboard
        self.redirect_uri_query_params = redirect_uri_query_params
        self.pkce_code_verifier = pkce_code_verifier


class Provider:
    def __init__(self, id: str):  # pylint: disable=redefined-builtin
        self.id = id
        self.config = ProviderConfigForClientType("temp")

    async def get_config_for_client_type(  # pylint: disable=no-self-use
        self, client_type: Optional[str], user_context: Dict[str, Any]
    ) -> ProviderConfigForClientType:
        _ = client_type
        __ = user_context
        raise NotImplementedError()

    async def get_authorisation_redirect_url(  # pylint: disable=no-self-use
        self,
        redirect_uri_on_provider_dashboard: str,
        tenant_id: str,
        user_context: Dict[str, Any],
    ) -> AuthorisationRedirect:
        _ = redirect_uri_on_provider_dashboard
        __ = tenant_id
        ___ = user_context
        raise NotImplementedError()

    async def exchange_auth_code_for_oauth_tokens(  # pylint: disable=no-self-use
        self,
        redirect_uri_info: RedirectUriInfo,
        user_context: Dict[str, Any],
    ) -> Dict[str, Any]:
        _ = redirect_uri_info
        __ = user_context
        raise NotImplementedError()

    async def get_user_info(  # pylint: disable=no-self-use
        self,
        oauth_tokens: Dict[str, Any],
        user_context: Dict[str, Any],
    ) -> UserInfo:
        _ = oauth_tokens
        __ = user_context
        raise NotImplementedError()


class ProviderClientConfig:
    def __init__(
        self,
        client_id: str,
        client_secret: Optional[str] = None,
        client_type: Optional[str] = None,
        scope: Optional[List[str]] = None,
        force_pkce: bool = False,
        additional_config: Optional[Dict[str, Any]] = None,
    ):
        self.client_id = client_id
        self.client_secret = client_secret
        self.client_type = client_type
        self.scope = scope
        self.force_pkce = force_pkce
        self.additional_config = additional_config

    def to_json(self) -> Dict[str, Any]:
        res = {
            "clientId": self.client_id,
            "clientSecret": self.client_secret,
            "clientType": self.client_type,
            "scope": self.scope,
            "forcePKCE": self.force_pkce,
            "additionalConfig": self.additional_config,
        }

        return {k: v for k, v in res.items() if v is not None}


class ProviderConfigForClientType:
    def __init__(
        self,
        client_id: str,
        client_secret: Optional[str] = None,
        scope: Optional[List[str]] = None,
        force_pkce: bool = False,
        additional_config: Optional[Dict[str, Any]] = None,
        name: Optional[str] = None,
        authorization_endpoint: Optional[str] = None,
        authorization_endpoint_query_params: Optional[
            Dict[str, Union[str, None]]
        ] = None,
        token_endpoint: Optional[str] = None,
        token_endpoint_body_params: Optional[Dict[str, Union[str, None]]] = None,
        user_info_endpoint: Optional[str] = None,
        user_info_endpoint_query_params: Optional[Dict[str, Union[str, None]]] = None,
        user_info_endpoint_headers: Optional[Dict[str, Union[str, None]]] = None,
        jwks_uri: Optional[str] = None,
        oidc_discovery_endpoint: Optional[str] = None,
        user_info_map: Optional[UserInfoMap] = None,
        require_email: bool = True,
        generate_fake_email: Optional[
            Callable[[str, Dict[str, Any]], Awaitable[str]]
        ] = None,
        validate_id_token_payload: Optional[
            Callable[
                [Dict[str, Any], ProviderConfigForClientType, Dict[str, Any]],
                Awaitable[None],
            ]
        ] = None,
    ):
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = scope
        self.force_pkce = force_pkce
        self.additional_config = additional_config

        self.name = name
        self.authorization_endpoint = authorization_endpoint
        self.authorization_endpoint_query_params = authorization_endpoint_query_params
        self.token_endpoint = token_endpoint
        self.token_endpoint_body_params = token_endpoint_body_params
        self.user_info_endpoint = user_info_endpoint
        self.user_info_endpoint_query_params = user_info_endpoint_query_params
        self.user_info_endpoint_headers = user_info_endpoint_headers
        self.jwks_uri = jwks_uri
        self.oidc_discovery_endpoint = oidc_discovery_endpoint
        self.user_info_map = user_info_map
        self.require_email = require_email
        self.validate_id_token_payload = validate_id_token_payload
        self.generate_fake_email = generate_fake_email


class UserFields:
    def __init__(
        self,
        user_id: Optional[str] = None,
        email: Optional[str] = None,
        email_verified: Optional[str] = None,
    ):
        self.user_id = user_id
        self.email = email
        self.email_verified = email_verified

    def to_json(self) -> Dict[str, Any]:
        res = {
            "userId": self.user_id,
            "email": self.email,
            "emailVerified": self.email_verified,
        }

        return {k: v for k, v in res.items() if v is not None}


class UserInfoMap:
    def __init__(
        self,
        from_id_token_payload: UserFields,
        from_user_info_api: UserFields,
    ):
        self.from_id_token_payload = from_id_token_payload
        self.from_user_info_api = from_user_info_api

    def to_json(self) -> Dict[str, Any]:
        return {
            "fromIdTokenPayload": self.from_id_token_payload.to_json(),
            "fromUserInfoAPI": self.from_user_info_api.to_json(),
        }


class ProviderConfig:
    def __init__(
        self,
        third_party_id: str,
        name: Optional[str] = None,
        clients: Optional[List[ProviderClientConfig]] = None,
        authorization_endpoint: Optional[str] = None,
        authorization_endpoint_query_params: Optional[
            Dict[str, Union[str, None]]
        ] = None,
        token_endpoint: Optional[str] = None,
        token_endpoint_body_params: Optional[Dict[str, Union[str, None]]] = None,
        user_info_endpoint: Optional[str] = None,
        user_info_endpoint_query_params: Optional[Dict[str, Union[str, None]]] = None,
        user_info_endpoint_headers: Optional[Dict[str, Union[str, None]]] = None,
        jwks_uri: Optional[str] = None,
        oidc_discovery_endpoint: Optional[str] = None,
        user_info_map: Optional[UserInfoMap] = None,
        require_email: bool = True,
        validate_id_token_payload: Optional[
            Callable[
                [Dict[str, Any], ProviderConfigForClientType, Dict[str, Any]],
                Awaitable[None],
            ]
        ] = None,
        generate_fake_email: Optional[
            Callable[[str, Dict[str, Any]], Awaitable[str]]
        ] = None,
    ):
        self.third_party_id = third_party_id
        self.name = name
        self.clients = clients
        self.authorization_endpoint = authorization_endpoint
        self.authorization_endpoint_query_params = authorization_endpoint_query_params
        self.token_endpoint = token_endpoint
        self.token_endpoint_body_params = token_endpoint_body_params
        self.user_info_endpoint = user_info_endpoint
        self.user_info_endpoint_query_params = user_info_endpoint_query_params
        self.user_info_endpoint_headers = user_info_endpoint_headers
        self.jwks_uri = jwks_uri
        self.oidc_discovery_endpoint = oidc_discovery_endpoint
        self.user_info_map = user_info_map
        self.require_email = require_email
        self.validate_id_token_payload = validate_id_token_payload
        self.generate_fake_email = generate_fake_email

    def to_json(self) -> Dict[str, Any]:
        res = {
            "thirdPartyId": self.third_party_id,
            "name": self.name,
            "clients": [c.to_json() for c in self.clients]
            if self.clients is not None
            else [],
            "authorizationEndpoint": self.authorization_endpoint,
            "authorizationEndpointQueryParams": self.authorization_endpoint_query_params,
            "tokenEndpoint": self.token_endpoint,
            "tokenEndpointBodyParams": self.token_endpoint_body_params,
            "userInfoEndpoint": self.user_info_endpoint,
            "userInfoEndpointQueryParams": self.user_info_endpoint_query_params,
            "userInfoEndpointHeaders": self.user_info_endpoint_headers,
            "jwksURI": self.jwks_uri,
            "oidcDiscoveryEndpoint": self.oidc_discovery_endpoint,
            "userInfoMap": self.user_info_map.to_json()
            if self.user_info_map is not None
            else None,
            "requireEmail": self.require_email,
        }

        return {k: v for k, v in res.items() if v is not None}


class ProviderInput:
    def __init__(
        self,
        config: ProviderConfig,
        override: Optional[Callable[[Provider], Provider]] = None,
    ):
        self.config = config
        self.override = override
