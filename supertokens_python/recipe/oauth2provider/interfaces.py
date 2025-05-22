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

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Dict, List, Optional, Union

from typing_extensions import Literal

from supertokens_python.recipe.session import SessionContainer
from supertokens_python.types import (
    RecipeUserId,
    User,
)
from supertokens_python.types.response import APIResponse, GeneralErrorResponse

from .oauth2_client import OAuth2Client

if TYPE_CHECKING:
    from supertokens_python.framework import BaseRequest, BaseResponse
    from supertokens_python.supertokens import AppInfo

    from .utils import OAuth2ProviderConfig


class ErrorOAuth2Response(APIResponse):
    def __init__(
        self,
        error: str,  # OAuth2 error format (e.g. invalid_request, login_required)
        error_description: str,  # Human readable error description
        status_code: Optional[int] = None,  # HTTP status code (e.g. 401 or 403)
    ):
        self.status: Literal["ERROR"] = "ERROR"
        self.error = error
        self.error_description = error_description
        self.status_code = status_code

    def to_json(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "status": self.status,
            "error": self.error,
            "errorDescription": self.error_description,
        }
        if self.status_code is not None:
            result["statusCode"] = self.status_code
        return result

    @staticmethod
    def from_json(json: Dict[str, Any]):
        return ErrorOAuth2Response(
            error=json["error"],
            error_description=json["errorDescription"],
            status_code=json["statusCode"],
        )


class ConsentRequestResponse:
    def __init__(
        self,
        challenge: str,  # ID/identifier of the consent authorization request
        acr: Optional[str] = None,  # Authentication Context Class Reference value
        amr: Optional[List[str]] = None,  # List of strings
        client: Optional[OAuth2Client] = None,
        context: Optional[Any] = None,  # Any JSON serializable object
        login_challenge: Optional[str] = None,  # Associated login challenge
        login_session_id: Optional[str] = None,
        oidc_context: Optional[Any] = None,  # Optional OpenID Connect request info
        requested_access_token_audience: Optional[List[str]] = None,
        requested_scope: Optional[List[str]] = None,
        skip: Optional[bool] = None,
        subject: Optional[str] = None,
    ):
        self.challenge = challenge
        self.acr = acr
        self.amr = amr
        self.client = client
        self.context = context
        self.login_challenge = login_challenge
        self.login_session_id = login_session_id
        self.oidc_context = oidc_context
        self.requested_access_token_audience = requested_access_token_audience
        self.requested_scope = requested_scope
        self.skip = skip
        self.subject = subject

    @staticmethod
    def from_json(json: Dict[str, Any]):
        return ConsentRequestResponse(
            acr=json["acr"],
            amr=json["amr"],
            challenge=json["challenge"],
            client=OAuth2Client.from_json(json["client"]),
            context=json["context"],
            login_challenge=json["loginChallenge"],
            login_session_id=json["loginSessionId"],
            oidc_context=json["oidcContext"],
            requested_access_token_audience=json["requestedAccessTokenAudience"],
            requested_scope=json["requestedScope"],
            skip=json["skip"],
            subject=json["subject"],
        )


class LoginRequestResponse:
    def __init__(
        self,
        challenge: str,  # ID/identifier of the login request
        client: OAuth2Client,
        request_url: str,  # Original OAuth 2.0 Authorization URL
        skip: bool,
        subject: str,
        oidc_context: Optional[Any] = None,  # Optional OpenID Connect request info
        requested_access_token_audience: Optional[List[str]] = None,
        requested_scope: Optional[List[str]] = None,
        session_id: Optional[str] = None,
    ):
        self.challenge = challenge
        self.client = client
        self.oidc_context = oidc_context
        self.request_url = request_url
        self.requested_access_token_audience = requested_access_token_audience
        self.requested_scope = requested_scope
        self.session_id = session_id
        self.skip = skip
        self.subject = subject

    @staticmethod
    def from_json(json: Dict[str, Any]):
        return LoginRequestResponse(
            challenge=json["challenge"],
            client=OAuth2Client.from_json(json["client"]),
            request_url=json["requestUrl"],
            skip=json["skip"],
            subject=json["subject"],
            oidc_context=json["oidcContext"],
            requested_access_token_audience=json["requestedAccessTokenAudience"],
            requested_scope=json["requestedScope"],
            session_id=json["sessionId"],
        )


class TokenInfoResponse:
    def __init__(
        self,
        expires_in: int,  # Lifetime in seconds of the access token
        scope: str,
        token_type: str,
        access_token: Optional[str] = None,
        id_token: Optional[str] = None,  # Requires id_token scope
        refresh_token: Optional[str] = None,  # Requires offline scope
    ):
        self.access_token = access_token
        self.expires_in = expires_in
        self.id_token = id_token
        self.refresh_token = refresh_token
        self.scope = scope
        self.token_type = token_type

    @staticmethod
    def from_json(json: Dict[str, Any]):
        return TokenInfoResponse(
            access_token=json.get("access_token"),
            expires_in=json["expires_in"],
            id_token=json.get("id_token"),
            refresh_token=json.get("refresh_token"),
            scope=json["scope"],
            token_type=json["token_type"],
        )

    def to_json(self) -> Dict[str, Any]:
        result = {
            "status": "OK",
            "expires_in": self.expires_in,
            "scope": self.scope,
            "token_type": self.token_type,
        }
        if self.access_token is not None:
            result["access_token"] = self.access_token
        if self.id_token is not None:
            result["id_token"] = self.id_token
        if self.refresh_token is not None:
            result["refresh_token"] = self.refresh_token
        return result


class LoginInfoResponse:
    def __init__(
        self,
        client_id: str,
        client_name: str,
        tos_uri: Optional[str] = None,
        policy_uri: Optional[str] = None,
        logo_uri: Optional[str] = None,
        client_uri: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.client_id = client_id
        self.client_name = client_name
        self.tos_uri = tos_uri
        self.policy_uri = policy_uri
        self.logo_uri = logo_uri
        self.client_uri = client_uri
        self.metadata = metadata

    def to_json(self) -> Dict[str, Any]:
        return {
            "status": "OK",
            "info": {
                "clientId": self.client_id,
                "clientName": self.client_name,
                "tosUri": self.tos_uri,
                "policyUri": self.policy_uri,
                "logoUri": self.logo_uri,
                "clientUri": self.client_uri,
                "metadata": self.metadata,
            },
        }


class RedirectResponse:
    def __init__(self, redirect_to: str, cookies: Optional[List[str]] = None):
        self.redirect_to = redirect_to
        self.cookies = cookies


class FrontendRedirectResponse:
    def __init__(self, frontend_redirect_to: str, cookies: Optional[List[str]] = None):
        self.frontend_redirect_to = frontend_redirect_to
        self.cookies = cookies

    def to_json(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "frontendRedirectTo": self.frontend_redirect_to,
        }
        return result


class OAuth2ClientsListResponse:
    def __init__(
        self, clients: List[OAuth2Client], next_pagination_token: Optional[str]
    ):
        self.clients = clients
        self.next_pagination_token = next_pagination_token

    @staticmethod
    def from_json(json: Dict[str, Any]):
        return OAuth2ClientsListResponse(
            clients=[OAuth2Client.from_json(client) for client in json["clients"]],
            next_pagination_token=json["nextPaginationToken"],
        )

    def to_json(self) -> Dict[str, Any]:
        result = {
            "status": "OK",
            "clients": [client.to_json() for client in self.clients],
        }
        if self.next_pagination_token is not None:
            result["nextPaginationToken"] = self.next_pagination_token
        return result


class OAuth2ClientResponse:
    def __init__(self, client: OAuth2Client):
        self.client = client

    @staticmethod
    def from_json(json: Dict[str, Any]):
        return OAuth2ClientResponse(client=OAuth2Client.from_json(json["client"]))


class CreatedOAuth2ClientResponse:
    def __init__(self, client: OAuth2Client):
        self.client = client

    @staticmethod
    def from_json(json: Dict[str, Any]):
        return CreatedOAuth2ClientResponse(
            client=OAuth2Client.from_json(json["client"])
        )

    def to_json(self) -> Dict[str, Any]:
        return {
            "status": "OK",
            "client": self.client.to_json(),
        }


class UpdatedOAuth2ClientResponse:
    def __init__(self, client: OAuth2Client):
        self.client = client

    @staticmethod
    def from_json(json: Dict[str, Any]):
        return UpdatedOAuth2ClientResponse(
            client=OAuth2Client.from_json(json["client"])
        )

    def to_json(self) -> Dict[str, Any]:
        return {
            "status": "OK",
            "client": self.client.to_json(),
        }


class DeleteOAuth2ClientOkResponse:
    def __init__(self):
        pass

    def to_json(self) -> Dict[str, Any]:
        return {
            "status": "OK",
        }


PayloadBuilderFunction = Callable[
    [User, List[str], str, Dict[str, Any]], Awaitable[Dict[str, Any]]
]

UserInfoBuilderFunction = Callable[
    [User, Dict[str, Any], List[str], str, Dict[str, Any]], Awaitable[Dict[str, Any]]
]


class OAuth2TokenValidationRequirements:
    def __init__(
        self,
        client_id: Optional[str] = None,
        scopes: Optional[List[str]] = None,
        audience: Optional[str] = None,
    ):
        self.client_id = client_id
        self.scopes = scopes
        self.audience = audience

    @staticmethod
    def from_json(json: Dict[str, Any]):
        return OAuth2TokenValidationRequirements(
            client_id=json.get("clientId"),
            scopes=json.get("scopes"),
            audience=json.get("audience"),
        )


class FrontendRedirectionURLTypeLogin:
    def __init__(
        self,
        login_challenge: str,
        tenant_id: str,
        force_fresh_auth: bool,
        hint: Optional[str] = None,
    ):
        self.login_challenge = login_challenge
        self.tenant_id = tenant_id
        self.force_fresh_auth = force_fresh_auth
        self.hint = hint


class FrontendRedirectionURLTypeTryRefresh:
    def __init__(self, login_challenge: str):
        self.login_challenge = login_challenge


class FrontendRedirectionURLTypeLogoutConfirmation:
    def __init__(self, logout_challenge: str):
        self.logout_challenge = logout_challenge


class FrontendRedirectionURLTypePostLogoutFallback:
    pass


class RevokeTokenUsingAuthorizationHeader:
    def __init__(self, token: str, authorization_header: str):
        self.token = token
        self.authorization_header = authorization_header


class RevokeTokenUsingClientIDAndClientSecret:
    def __init__(self, token: str, client_id: str, client_secret: Optional[str]):
        self.token = token
        self.client_id = client_id
        self.client_secret = client_secret


class InactiveTokenResponse:
    def to_json(self):
        return {"active": False}


class ActiveTokenResponse:
    def __init__(self, payload: Dict[str, Any]):
        self.payload = payload

    def to_json(self):
        return {"active": True, **self.payload}


class ValidatedAccessTokenResponse:
    def __init__(self, payload: Dict[str, Any]):
        self.payload = payload

    def to_json(self):
        return {"payload": self.payload}


class RevokeTokenOkResponse:
    def to_json(self):
        return {"status": "OK"}


class UserInfoResponse:
    def __init__(self, payload: Dict[str, Any]):
        self.payload = payload

    def to_json(self):
        return self.payload


class OAuth2ClientOptions:
    def __init__(
        self,
        client_id: str,
        client_secret: Optional[str],
        created_at: str,
        updated_at: str,
        client_name: str,
        scope: str,
        redirect_uris: Optional[List[str]],
        post_logout_redirect_uris: Optional[List[str]],
        authorization_code_grant_access_token_lifespan: Optional[str],
        authorization_code_grant_id_token_lifespan: Optional[str],
        authorization_code_grant_refresh_token_lifespan: Optional[str],
        client_credentials_grant_access_token_lifespan: Optional[str],
        implicit_grant_access_token_lifespan: Optional[str],
        implicit_grant_id_token_lifespan: Optional[str],
        refresh_token_grant_access_token_lifespan: Optional[str],
        refresh_token_grant_id_token_lifespan: Optional[str],
        refresh_token_grant_refresh_token_lifespan: Optional[str],
        token_endpoint_auth_method: str,
        audience: Optional[List[str]],
        grant_types: Optional[List[str]],
        response_types: Optional[List[str]],
        client_uri: Optional[str],
        logo_uri: Optional[str],
        policy_uri: Optional[str],
        tos_uri: Optional[str],
        metadata: Optional[Dict[str, Any]],
        enable_refresh_token_rotation: Optional[bool],
    ):
        self.client_id = client_id
        self.client_secret = client_secret
        self.created_at = created_at
        self.updated_at = updated_at
        self.client_name = client_name
        self.scope = scope
        self.redirect_uris = redirect_uris
        self.post_logout_redirect_uris = post_logout_redirect_uris
        self.authorization_code_grant_access_token_lifespan = (
            authorization_code_grant_access_token_lifespan
        )
        self.authorization_code_grant_id_token_lifespan = (
            authorization_code_grant_id_token_lifespan
        )
        self.authorization_code_grant_refresh_token_lifespan = (
            authorization_code_grant_refresh_token_lifespan
        )
        self.client_credentials_grant_access_token_lifespan = (
            client_credentials_grant_access_token_lifespan
        )
        self.implicit_grant_access_token_lifespan = implicit_grant_access_token_lifespan
        self.implicit_grant_id_token_lifespan = implicit_grant_id_token_lifespan
        self.refresh_token_grant_access_token_lifespan = (
            refresh_token_grant_access_token_lifespan
        )
        self.refresh_token_grant_id_token_lifespan = (
            refresh_token_grant_id_token_lifespan
        )
        self.refresh_token_grant_refresh_token_lifespan = (
            refresh_token_grant_refresh_token_lifespan
        )
        self.token_endpoint_auth_method = token_endpoint_auth_method
        self.audience = audience
        self.grant_types = grant_types
        self.response_types = response_types
        self.client_uri = client_uri
        self.logo_uri = logo_uri
        self.policy_uri = policy_uri
        self.tos_uri = tos_uri
        self.metadata = metadata
        self.enable_refresh_token_rotation = enable_refresh_token_rotation

    def to_json(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "clientId": self.client_id,
            "createdAt": self.created_at,
            "updatedAt": self.updated_at,
            "clientName": self.client_name,
            "scope": self.scope,
            "tokenEndpointAuthMethod": self.token_endpoint_auth_method,
        }
        if self.client_secret is not None:
            result["clientSecret"] = self.client_secret
        if self.redirect_uris is not None:
            result["redirectUris"] = self.redirect_uris
        if self.post_logout_redirect_uris is not None:
            result["postLogoutRedirectUris"] = self.post_logout_redirect_uris
        if self.authorization_code_grant_access_token_lifespan is not None:
            result["authorizationCodeGrantAccessTokenLifespan"] = (
                self.authorization_code_grant_access_token_lifespan
            )
        if self.authorization_code_grant_id_token_lifespan is not None:
            result["authorizationCodeGrantIdTokenLifespan"] = (
                self.authorization_code_grant_id_token_lifespan
            )
        if self.authorization_code_grant_refresh_token_lifespan is not None:
            result["authorizationCodeGrantRefreshTokenLifespan"] = (
                self.authorization_code_grant_refresh_token_lifespan
            )
        if self.client_credentials_grant_access_token_lifespan is not None:
            result["clientCredentialsGrantAccessTokenLifespan"] = (
                self.client_credentials_grant_access_token_lifespan
            )
        if self.implicit_grant_access_token_lifespan is not None:
            result["implicitGrantAccessTokenLifespan"] = (
                self.implicit_grant_access_token_lifespan
            )
        if self.implicit_grant_id_token_lifespan is not None:
            result["implicitGrantIdTokenLifespan"] = (
                self.implicit_grant_id_token_lifespan
            )
        if self.refresh_token_grant_access_token_lifespan is not None:
            result["refreshTokenGrantAccessTokenLifespan"] = (
                self.refresh_token_grant_access_token_lifespan
            )
        if self.refresh_token_grant_id_token_lifespan is not None:
            result["refreshTokenGrantIdTokenLifespan"] = (
                self.refresh_token_grant_id_token_lifespan
            )
        if self.refresh_token_grant_refresh_token_lifespan is not None:
            result["refreshTokenGrantRefreshTokenLifespan"] = (
                self.refresh_token_grant_refresh_token_lifespan
            )
        if self.audience is not None:
            result["audience"] = self.audience
        if self.grant_types is not None:
            result["grantTypes"] = self.grant_types
        if self.response_types is not None:
            result["responseTypes"] = self.response_types
        if self.client_uri is not None:
            result["clientUri"] = self.client_uri
        if self.logo_uri is not None:
            result["logoUri"] = self.logo_uri
        if self.policy_uri is not None:
            result["policyUri"] = self.policy_uri
        if self.tos_uri is not None:
            result["tosUri"] = self.tos_uri
        if self.metadata is not None:
            result["metadata"] = self.metadata
        if self.enable_refresh_token_rotation is not None:
            result["enableRefreshTokenRotation"] = self.enable_refresh_token_rotation
        return result

    @staticmethod
    def from_json(json: Dict[str, Any]) -> "OAuth2ClientOptions":
        return OAuth2ClientOptions(
            client_id=json["clientId"],
            client_secret=json["clientSecret"],
            created_at=json["createdAt"],
            updated_at=json["updatedAt"],
            client_name=json["clientName"],
            scope=json["scope"],
            redirect_uris=json["redirectUris"],
            post_logout_redirect_uris=json["postLogoutRedirectUris"],
            authorization_code_grant_access_token_lifespan=json.get(
                "authorizationCodeGrantAccessTokenLifespan"
            ),
            authorization_code_grant_id_token_lifespan=json.get(
                "authorizationCodeGrantIdTokenLifespan"
            ),
            authorization_code_grant_refresh_token_lifespan=json.get(
                "authorizationCodeGrantRefreshTokenLifespan"
            ),
            client_credentials_grant_access_token_lifespan=json.get(
                "clientCredentialsGrantAccessTokenLifespan"
            ),
            implicit_grant_access_token_lifespan=json.get(
                "implicitGrantAccessTokenLifespan"
            ),
            implicit_grant_id_token_lifespan=json.get("implicitGrantIdTokenLifespan"),
            refresh_token_grant_access_token_lifespan=json.get(
                "refreshTokenGrantAccessTokenLifespan"
            ),
            refresh_token_grant_id_token_lifespan=json.get(
                "refreshTokenGrantIdTokenLifespan"
            ),
            refresh_token_grant_refresh_token_lifespan=json.get(
                "refreshTokenGrantRefreshTokenLifespan"
            ),
            token_endpoint_auth_method=json["tokenEndpointAuthMethod"],
            audience=json.get("audience"),
            grant_types=json.get("grantTypes"),
            response_types=json.get("responseTypes"),
            client_uri=json.get("clientUri"),
            logo_uri=json.get("logoUri"),
            policy_uri=json.get("policyUri"),
            tos_uri=json.get("tosUri"),
            metadata=json.get("metadata"),
            enable_refresh_token_rotation=json.get("enableRefreshTokenRotation"),
        )


class CreateOAuth2ClientInput:
    def __init__(
        self,
        client_id: Optional[str],
        client_secret: Optional[str],
        client_name: Optional[str],
        scope: Optional[str],
        redirect_uris: Optional[List[str]],
        post_logout_redirect_uris: Optional[List[str]],
        authorization_code_grant_access_token_lifespan: Optional[str],
        authorization_code_grant_id_token_lifespan: Optional[str],
        authorization_code_grant_refresh_token_lifespan: Optional[str],
        client_credentials_grant_access_token_lifespan: Optional[str],
        implicit_grant_access_token_lifespan: Optional[str],
        implicit_grant_id_token_lifespan: Optional[str],
        refresh_token_grant_access_token_lifespan: Optional[str],
        refresh_token_grant_id_token_lifespan: Optional[str],
        refresh_token_grant_refresh_token_lifespan: Optional[str],
        token_endpoint_auth_method: Optional[str],
        audience: Optional[List[str]],
        grant_types: Optional[List[str]],
        response_types: Optional[List[str]],
        client_uri: Optional[str],
        logo_uri: Optional[str],
        policy_uri: Optional[str],
        tos_uri: Optional[str],
        metadata: Optional[Dict[str, Any]],
        enable_refresh_token_rotation: Optional[bool],
    ):
        self.client_id = client_id
        self.client_secret = client_secret
        self.client_name = client_name
        self.scope = scope
        self.redirect_uris = redirect_uris
        self.post_logout_redirect_uris = post_logout_redirect_uris
        self.authorization_code_grant_access_token_lifespan = (
            authorization_code_grant_access_token_lifespan
        )
        self.authorization_code_grant_id_token_lifespan = (
            authorization_code_grant_id_token_lifespan
        )
        self.authorization_code_grant_refresh_token_lifespan = (
            authorization_code_grant_refresh_token_lifespan
        )
        self.client_credentials_grant_access_token_lifespan = (
            client_credentials_grant_access_token_lifespan
        )
        self.implicit_grant_access_token_lifespan = implicit_grant_access_token_lifespan
        self.implicit_grant_id_token_lifespan = implicit_grant_id_token_lifespan
        self.refresh_token_grant_access_token_lifespan = (
            refresh_token_grant_access_token_lifespan
        )
        self.refresh_token_grant_id_token_lifespan = (
            refresh_token_grant_id_token_lifespan
        )
        self.refresh_token_grant_refresh_token_lifespan = (
            refresh_token_grant_refresh_token_lifespan
        )
        self.token_endpoint_auth_method = token_endpoint_auth_method
        self.audience = audience
        self.grant_types = grant_types
        self.response_types = response_types
        self.client_uri = client_uri
        self.logo_uri = logo_uri
        self.policy_uri = policy_uri
        self.tos_uri = tos_uri
        self.metadata = metadata
        self.enable_refresh_token_rotation = enable_refresh_token_rotation

    def to_json(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        if self.client_id is not None:
            result["clientId"] = self.client_id
        if self.client_name is not None:
            result["clientName"] = self.client_name
        if self.scope is not None:
            result["scope"] = self.scope
        if self.token_endpoint_auth_method is not None:
            result["tokenEndpointAuthMethod"] = self.token_endpoint_auth_method
        if self.client_secret is not None:
            result["clientSecret"] = self.client_secret
        if self.redirect_uris is not None:
            result["redirectUris"] = self.redirect_uris
        if self.post_logout_redirect_uris is not None:
            result["postLogoutRedirectUris"] = self.post_logout_redirect_uris
        if self.authorization_code_grant_access_token_lifespan is not None:
            result["authorizationCodeGrantAccessTokenLifespan"] = (
                self.authorization_code_grant_access_token_lifespan
            )
        if self.authorization_code_grant_id_token_lifespan is not None:
            result["authorizationCodeGrantIdTokenLifespan"] = (
                self.authorization_code_grant_id_token_lifespan
            )
        if self.authorization_code_grant_refresh_token_lifespan is not None:
            result["authorizationCodeGrantRefreshTokenLifespan"] = (
                self.authorization_code_grant_refresh_token_lifespan
            )
        if self.client_credentials_grant_access_token_lifespan is not None:
            result["clientCredentialsGrantAccessTokenLifespan"] = (
                self.client_credentials_grant_access_token_lifespan
            )
        if self.implicit_grant_access_token_lifespan is not None:
            result["implicitGrantAccessTokenLifespan"] = (
                self.implicit_grant_access_token_lifespan
            )
        if self.implicit_grant_id_token_lifespan is not None:
            result["implicitGrantIdTokenLifespan"] = (
                self.implicit_grant_id_token_lifespan
            )
        if self.refresh_token_grant_access_token_lifespan is not None:
            result["refreshTokenGrantAccessTokenLifespan"] = (
                self.refresh_token_grant_access_token_lifespan
            )
        if self.refresh_token_grant_id_token_lifespan is not None:
            result["refreshTokenGrantIdTokenLifespan"] = (
                self.refresh_token_grant_id_token_lifespan
            )
        if self.refresh_token_grant_refresh_token_lifespan is not None:
            result["refreshTokenGrantRefreshTokenLifespan"] = (
                self.refresh_token_grant_refresh_token_lifespan
            )
        if self.audience is not None:
            result["audience"] = self.audience
        if self.grant_types is not None:
            result["grantTypes"] = self.grant_types
        if self.response_types is not None:
            result["responseTypes"] = self.response_types
        if self.client_uri is not None:
            result["clientUri"] = self.client_uri
        if self.logo_uri is not None:
            result["logoUri"] = self.logo_uri
        if self.policy_uri is not None:
            result["policyUri"] = self.policy_uri
        if self.tos_uri is not None:
            result["tosUri"] = self.tos_uri
        if self.metadata is not None:
            result["metadata"] = self.metadata
        if self.enable_refresh_token_rotation is not None:
            result["enableRefreshTokenRotation"] = self.enable_refresh_token_rotation
        return result

    @staticmethod
    def from_json(json: Dict[str, Any]) -> "CreateOAuth2ClientInput":
        return CreateOAuth2ClientInput(
            client_id=json.get("clientId"),
            client_secret=json.get("clientSecret"),
            client_name=json.get("clientName"),
            scope=json.get("scope"),
            redirect_uris=json.get("redirectUris"),
            post_logout_redirect_uris=json.get("postLogoutRedirectUris"),
            authorization_code_grant_access_token_lifespan=json.get(
                "authorizationCodeGrantAccessTokenLifespan"
            ),
            authorization_code_grant_id_token_lifespan=json.get(
                "authorizationCodeGrantIdTokenLifespan"
            ),
            authorization_code_grant_refresh_token_lifespan=json.get(
                "authorizationCodeGrantRefreshTokenLifespan"
            ),
            client_credentials_grant_access_token_lifespan=json.get(
                "clientCredentialsGrantAccessTokenLifespan"
            ),
            implicit_grant_access_token_lifespan=json.get(
                "implicitGrantAccessTokenLifespan"
            ),
            implicit_grant_id_token_lifespan=json.get("implicitGrantIdTokenLifespan"),
            refresh_token_grant_access_token_lifespan=json.get(
                "refreshTokenGrantAccessTokenLifespan"
            ),
            refresh_token_grant_id_token_lifespan=json.get(
                "refreshTokenGrantIdTokenLifespan"
            ),
            refresh_token_grant_refresh_token_lifespan=json.get(
                "refreshTokenGrantRefreshTokenLifespan"
            ),
            token_endpoint_auth_method=json.get("tokenEndpointAuthMethod"),
            audience=json.get("audience"),
            grant_types=json.get("grantTypes"),
            response_types=json.get("responseTypes"),
            client_uri=json.get("clientUri"),
            logo_uri=json.get("logoUri"),
            policy_uri=json.get("policyUri"),
            tos_uri=json.get("tosUri"),
            metadata=json.get("metadata"),
            enable_refresh_token_rotation=json.get("enableRefreshTokenRotation"),
        )


class NotSet:
    pass


class UpdateOAuth2ClientInput:
    def __init__(
        self,
        client_id: str,
        client_secret: Union[Optional[str], NotSet] = NotSet(),
        client_name: Union[Optional[str], NotSet] = NotSet(),
        scope: Union[Optional[str], NotSet] = NotSet(),
        redirect_uris: Union[Optional[List[str]], NotSet] = NotSet(),
        post_logout_redirect_uris: Union[Optional[List[str]], NotSet] = NotSet(),
        authorization_code_grant_access_token_lifespan: Union[
            Optional[str], NotSet
        ] = NotSet(),
        authorization_code_grant_id_token_lifespan: Union[
            Optional[str], NotSet
        ] = NotSet(),
        authorization_code_grant_refresh_token_lifespan: Union[
            Optional[str], NotSet
        ] = NotSet(),
        client_credentials_grant_access_token_lifespan: Union[
            Optional[str], NotSet
        ] = NotSet(),
        implicit_grant_access_token_lifespan: Union[Optional[str], NotSet] = NotSet(),
        implicit_grant_id_token_lifespan: Union[Optional[str], NotSet] = NotSet(),
        refresh_token_grant_access_token_lifespan: Union[
            Optional[str], NotSet
        ] = NotSet(),
        refresh_token_grant_id_token_lifespan: Union[Optional[str], NotSet] = NotSet(),
        refresh_token_grant_refresh_token_lifespan: Union[
            Optional[str], NotSet
        ] = NotSet(),
        token_endpoint_auth_method: Union[Optional[str], NotSet] = NotSet(),
        audience: Union[Optional[List[str]], NotSet] = NotSet(),
        grant_types: Union[Optional[List[str]], NotSet] = NotSet(),
        response_types: Union[Optional[List[str]], NotSet] = NotSet(),
        client_uri: Union[Optional[str], NotSet] = NotSet(),
        logo_uri: Union[Optional[str], NotSet] = NotSet(),
        policy_uri: Union[Optional[str], NotSet] = NotSet(),
        tos_uri: Union[Optional[str], NotSet] = NotSet(),
        metadata: Union[Optional[Dict[str, Any]], NotSet] = NotSet(),
        enable_refresh_token_rotation: Union[Optional[bool], NotSet] = NotSet(),
    ):
        self.client_id = client_id
        self.client_secret = client_secret
        self.client_name = client_name
        self.scope = scope
        self.redirect_uris = redirect_uris
        self.post_logout_redirect_uris = post_logout_redirect_uris
        self.authorization_code_grant_access_token_lifespan = (
            authorization_code_grant_access_token_lifespan
        )
        self.authorization_code_grant_id_token_lifespan = (
            authorization_code_grant_id_token_lifespan
        )
        self.authorization_code_grant_refresh_token_lifespan = (
            authorization_code_grant_refresh_token_lifespan
        )
        self.client_credentials_grant_access_token_lifespan = (
            client_credentials_grant_access_token_lifespan
        )
        self.implicit_grant_access_token_lifespan = implicit_grant_access_token_lifespan
        self.implicit_grant_id_token_lifespan = implicit_grant_id_token_lifespan
        self.refresh_token_grant_access_token_lifespan = (
            refresh_token_grant_access_token_lifespan
        )
        self.refresh_token_grant_id_token_lifespan = (
            refresh_token_grant_id_token_lifespan
        )
        self.refresh_token_grant_refresh_token_lifespan = (
            refresh_token_grant_refresh_token_lifespan
        )
        self.token_endpoint_auth_method = token_endpoint_auth_method
        self.audience = audience
        self.grant_types = grant_types
        self.response_types = response_types
        self.client_uri = client_uri
        self.logo_uri = logo_uri
        self.policy_uri = policy_uri
        self.tos_uri = tos_uri
        self.metadata = metadata
        self.enable_refresh_token_rotation = enable_refresh_token_rotation

    def to_json(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        result["clientId"] = self.client_id

        if not isinstance(self.client_name, NotSet):
            result["clientName"] = self.client_name
        if not isinstance(self.scope, NotSet):
            result["scope"] = self.scope
        if not isinstance(self.token_endpoint_auth_method, NotSet):
            result["tokenEndpointAuthMethod"] = self.token_endpoint_auth_method
        if not isinstance(self.client_secret, NotSet):
            result["clientSecret"] = self.client_secret
        if not isinstance(self.redirect_uris, NotSet):
            result["redirectUris"] = self.redirect_uris
        if not isinstance(self.post_logout_redirect_uris, NotSet):
            result["postLogoutRedirectUris"] = self.post_logout_redirect_uris
        if not isinstance(self.authorization_code_grant_access_token_lifespan, NotSet):
            result["authorizationCodeGrantAccessTokenLifespan"] = (
                self.authorization_code_grant_access_token_lifespan
            )
        if not isinstance(self.authorization_code_grant_id_token_lifespan, NotSet):
            result["authorizationCodeGrantIdTokenLifespan"] = (
                self.authorization_code_grant_id_token_lifespan
            )
        if not isinstance(self.authorization_code_grant_refresh_token_lifespan, NotSet):
            result["authorizationCodeGrantRefreshTokenLifespan"] = (
                self.authorization_code_grant_refresh_token_lifespan
            )
        if not isinstance(self.client_credentials_grant_access_token_lifespan, NotSet):
            result["clientCredentialsGrantAccessTokenLifespan"] = (
                self.client_credentials_grant_access_token_lifespan
            )
        if not isinstance(self.implicit_grant_access_token_lifespan, NotSet):
            result["implicitGrantAccessTokenLifespan"] = (
                self.implicit_grant_access_token_lifespan
            )
        if not isinstance(self.implicit_grant_id_token_lifespan, NotSet):
            result["implicitGrantIdTokenLifespan"] = (
                self.implicit_grant_id_token_lifespan
            )
        if not isinstance(self.refresh_token_grant_access_token_lifespan, NotSet):
            result["refreshTokenGrantAccessTokenLifespan"] = (
                self.refresh_token_grant_access_token_lifespan
            )
        if not isinstance(self.refresh_token_grant_id_token_lifespan, NotSet):
            result["refreshTokenGrantIdTokenLifespan"] = (
                self.refresh_token_grant_id_token_lifespan
            )
        if not isinstance(self.refresh_token_grant_refresh_token_lifespan, NotSet):
            result["refreshTokenGrantRefreshTokenLifespan"] = (
                self.refresh_token_grant_refresh_token_lifespan
            )
        if not isinstance(self.audience, NotSet):
            result["audience"] = self.audience
        if not isinstance(self.grant_types, NotSet):
            result["grantTypes"] = self.grant_types
        if not isinstance(self.response_types, NotSet):
            result["responseTypes"] = self.response_types
        if not isinstance(self.client_uri, NotSet):
            result["clientUri"] = self.client_uri
        if not isinstance(self.logo_uri, NotSet):
            result["logoUri"] = self.logo_uri
        if not isinstance(self.policy_uri, NotSet):
            result["policyUri"] = self.policy_uri
        if not isinstance(self.tos_uri, NotSet):
            result["tosUri"] = self.tos_uri
        if not isinstance(self.metadata, NotSet):
            result["metadata"] = self.metadata
        if not isinstance(self.enable_refresh_token_rotation, NotSet):
            result["enableRefreshTokenRotation"] = self.enable_refresh_token_rotation
        return result

    @staticmethod
    def from_json(json: Dict[str, Any]) -> "UpdateOAuth2ClientInput":
        return UpdateOAuth2ClientInput(
            client_id=json["clientId"],
            client_secret=json.get("clientSecret", NotSet()),
            client_name=json.get("clientName", NotSet()),
            scope=json.get("scope", NotSet()),
            redirect_uris=json.get("redirectUris", NotSet()),
            post_logout_redirect_uris=json.get("postLogoutRedirectUris", NotSet()),
            authorization_code_grant_access_token_lifespan=json.get(
                "authorizationCodeGrantAccessTokenLifespan", NotSet()
            ),
            authorization_code_grant_id_token_lifespan=json.get(
                "authorizationCodeGrantIdTokenLifespan", NotSet()
            ),
            authorization_code_grant_refresh_token_lifespan=json.get(
                "authorizationCodeGrantRefreshTokenLifespan", NotSet()
            ),
            client_credentials_grant_access_token_lifespan=json.get(
                "clientCredentialsGrantAccessTokenLifespan", NotSet()
            ),
            implicit_grant_access_token_lifespan=json.get(
                "implicitGrantAccessTokenLifespan", NotSet()
            ),
            implicit_grant_id_token_lifespan=json.get(
                "implicitGrantIdTokenLifespan", NotSet()
            ),
            refresh_token_grant_access_token_lifespan=json.get(
                "refreshTokenGrantAccessTokenLifespan", NotSet()
            ),
            refresh_token_grant_id_token_lifespan=json.get(
                "refreshTokenGrantIdTokenLifespan", NotSet()
            ),
            refresh_token_grant_refresh_token_lifespan=json.get(
                "refreshTokenGrantRefreshTokenLifespan", NotSet()
            ),
            token_endpoint_auth_method=json.get("tokenEndpointAuthMethod", NotSet()),
            audience=json.get("audience", NotSet()),
            grant_types=json.get("grantTypes", NotSet()),
            response_types=json.get("responseTypes", NotSet()),
            client_uri=json.get("clientUri", NotSet()),
            logo_uri=json.get("logoUri", NotSet()),
            policy_uri=json.get("policyUri", NotSet()),
            tos_uri=json.get("tosUri", NotSet()),
            metadata=json.get("metadata", NotSet()),
            enable_refresh_token_rotation=json.get(
                "enableRefreshTokenRotation", NotSet()
            ),
        )


class RecipeInterface(ABC):
    @abstractmethod
    async def authorization(
        self,
        params: Dict[str, str],
        cookies: Optional[str],
        session: Optional[SessionContainer],
        user_context: Dict[str, Any],
    ) -> Union[RedirectResponse, ErrorOAuth2Response]:
        pass

    @abstractmethod
    async def token_exchange(
        self,
        authorization_header: Optional[str],
        body: Dict[str, Optional[str]],
        user_context: Dict[str, Any],
    ) -> Union[TokenInfoResponse, ErrorOAuth2Response]:
        pass

    @abstractmethod
    async def get_consent_request(
        self, challenge: str, user_context: Dict[str, Any]
    ) -> ConsentRequestResponse:
        pass

    @abstractmethod
    async def accept_consent_request(
        self,
        challenge: str,
        context: Optional[Any],
        grant_access_token_audience: Optional[List[str]],
        grant_scope: Optional[List[str]],
        handled_at: Optional[str],
        tenant_id: str,
        rsub: str,
        session_handle: str,
        initial_access_token_payload: Optional[Dict[str, Any]],
        initial_id_token_payload: Optional[Dict[str, Any]],
        user_context: Dict[str, Any],
    ) -> RedirectResponse:
        pass

    @abstractmethod
    async def reject_consent_request(
        self, challenge: str, error: ErrorOAuth2Response, user_context: Dict[str, Any]
    ) -> RedirectResponse:
        pass

    @abstractmethod
    async def get_login_request(
        self, challenge: str, user_context: Dict[str, Any]
    ) -> Union[LoginRequestResponse, ErrorOAuth2Response]:
        pass

    @abstractmethod
    async def accept_login_request(
        self,
        challenge: str,
        acr: Optional[str],
        amr: Optional[List[str]],
        context: Optional[Any],
        extend_session_lifespan: Optional[bool],
        identity_provider_session_id: Optional[str],
        subject: str,
        user_context: Dict[str, Any],
    ) -> RedirectResponse:
        pass

    @abstractmethod
    async def reject_login_request(
        self,
        challenge: str,
        error: ErrorOAuth2Response,
        user_context: Dict[str, Any],
    ) -> RedirectResponse:
        pass

    @abstractmethod
    async def get_oauth2_clients(
        self,
        page_size: Optional[int],
        pagination_token: Optional[str],
        client_name: Optional[str],
        user_context: Dict[str, Any],
    ) -> Union[OAuth2ClientsListResponse, ErrorOAuth2Response]:
        pass

    @abstractmethod
    async def get_oauth2_client(
        self,
        client_id: str,
        user_context: Dict[str, Any],
    ) -> Union[OAuth2ClientResponse, ErrorOAuth2Response]:
        pass

    @abstractmethod
    async def create_oauth2_client(
        self,
        params: CreateOAuth2ClientInput,
        user_context: Dict[str, Any],
    ) -> Union[CreatedOAuth2ClientResponse, ErrorOAuth2Response]:
        pass

    @abstractmethod
    async def update_oauth2_client(
        self,
        params: UpdateOAuth2ClientInput,
        user_context: Dict[str, Any],
    ) -> Union[UpdatedOAuth2ClientResponse, ErrorOAuth2Response]:
        pass

    @abstractmethod
    async def delete_oauth2_client(
        self,
        client_id: str,
        user_context: Dict[str, Any],
    ) -> Union[DeleteOAuth2ClientOkResponse, ErrorOAuth2Response]:
        pass

    @abstractmethod
    async def validate_oauth2_access_token(
        self,
        token: str,
        requirements: Optional[OAuth2TokenValidationRequirements],
        check_database: Optional[bool],
        user_context: Dict[str, Any],
    ) -> ValidatedAccessTokenResponse:
        pass

    @abstractmethod
    async def get_requested_scopes(
        self,
        recipe_user_id: Optional[RecipeUserId],
        session_handle: Optional[str],
        scope_param: List[str],
        client_id: str,
        user_context: Dict[str, Any],
    ) -> List[str]:
        pass

    @abstractmethod
    async def build_access_token_payload(
        self,
        user: Optional[User],
        client: OAuth2Client,
        session_handle: Optional[str],
        scopes: List[str],
        user_context: Dict[str, Any],
    ) -> Dict[str, Any]:
        pass

    @abstractmethod
    async def build_id_token_payload(
        self,
        user: Optional[User],
        client: OAuth2Client,
        session_handle: Optional[str],
        scopes: List[str],
        user_context: Dict[str, Any],
    ) -> Dict[str, Any]:
        pass

    @abstractmethod
    async def build_user_info(
        self,
        user: User,
        access_token_payload: Dict[str, Any],
        scopes: List[str],
        tenant_id: str,
        user_context: Dict[str, Any],
    ) -> Dict[str, Any]:
        pass

    @abstractmethod
    async def get_frontend_redirection_url(
        self,
        params: Union[
            FrontendRedirectionURLTypeLogin,
            FrontendRedirectionURLTypeTryRefresh,
            FrontendRedirectionURLTypeLogoutConfirmation,
            FrontendRedirectionURLTypePostLogoutFallback,
        ],
        user_context: Dict[str, Any],
    ) -> str:
        pass

    @abstractmethod
    async def revoke_token(
        self,
        params: Union[
            RevokeTokenUsingAuthorizationHeader,
            RevokeTokenUsingClientIDAndClientSecret,
        ],
        user_context: Dict[str, Any],
    ) -> Union[RevokeTokenOkResponse, ErrorOAuth2Response]:
        pass

    @abstractmethod
    async def revoke_tokens_by_client_id(
        self,
        client_id: str,
        user_context: Dict[str, Any],
    ):
        pass

    @abstractmethod
    async def revoke_tokens_by_session_handle(
        self,
        session_handle: str,
        user_context: Dict[str, Any],
    ):
        pass

    @abstractmethod
    async def introspect_token(
        self,
        token: str,
        scopes: Optional[List[str]],
        user_context: Dict[str, Any],
    ) -> Union[ActiveTokenResponse, InactiveTokenResponse]:
        pass

    @abstractmethod
    async def end_session(
        self,
        params: Dict[str, str],
        should_try_refresh: bool,
        session: Optional[SessionContainer],
        user_context: Dict[str, Any],
    ) -> Union[RedirectResponse, ErrorOAuth2Response]:
        pass

    @abstractmethod
    async def accept_logout_request(
        self,
        challenge: str,
        user_context: Dict[str, Any],
    ) -> Union[RedirectResponse, ErrorOAuth2Response]:
        pass

    @abstractmethod
    async def reject_logout_request(
        self,
        challenge: str,
        user_context: Dict[str, Any],
    ):
        pass


class APIOptions:
    def __init__(
        self,
        app_info: AppInfo,
        request: BaseRequest,
        response: BaseResponse,
        recipe_id: str,
        config: OAuth2ProviderConfig,
        recipe_implementation: RecipeInterface,
    ):
        self.app_info: AppInfo = app_info
        self.request: BaseRequest = request
        self.response: BaseResponse = response
        self.recipe_id: str = recipe_id
        self.config: OAuth2ProviderConfig = config
        self.recipe_implementation: RecipeInterface = recipe_implementation


class APIInterface:
    def __init__(self):
        self.disable_login_get = False
        self.disable_auth_get = False
        self.disable_token_post = False
        self.disable_login_info_get = False
        self.disable_user_info_get = False
        self.disable_revoke_token_post = False
        self.disable_introspect_token_post = False
        self.disable_end_session_get = False
        self.disable_end_session_post = False
        self.disable_logout_post = False

    @abstractmethod
    async def login_get(
        self,
        login_challenge: str,
        options: APIOptions,
        session: Optional[SessionContainer],
        should_try_refresh: bool,
        user_context: Dict[str, Any],
    ) -> Union[FrontendRedirectResponse, ErrorOAuth2Response, GeneralErrorResponse]:
        pass

    @abstractmethod
    async def auth_get(
        self,
        params: Any,
        cookie: Optional[str],
        session: Optional[SessionContainer],
        should_try_refresh: bool,
        options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[RedirectResponse, ErrorOAuth2Response, GeneralErrorResponse]:
        pass

    @abstractmethod
    async def token_post(
        self,
        authorization_header: Optional[str],
        body: Any,
        options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[TokenInfoResponse, ErrorOAuth2Response, GeneralErrorResponse]:
        pass

    @abstractmethod
    async def login_info_get(
        self,
        login_challenge: str,
        options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[
        LoginInfoResponse,
        ErrorOAuth2Response,
        GeneralErrorResponse,
    ]:
        pass

    @abstractmethod
    async def user_info_get(
        self,
        access_token_payload: Dict[str, Any],
        user: User,
        scopes: List[str],
        tenant_id: str,
        options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[UserInfoResponse, GeneralErrorResponse]:
        pass

    @abstractmethod
    async def revoke_token_post(
        self,
        options: APIOptions,
        token: str,
        authorization_header: Optional[str],
        client_id: Optional[str],
        client_secret: Optional[str],
        user_context: Dict[str, Any],
    ) -> Union[RevokeTokenOkResponse, ErrorOAuth2Response, GeneralErrorResponse]:
        pass

    @abstractmethod
    async def introspect_token_post(
        self,
        token: str,
        scopes: Optional[List[str]],
        options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[ActiveTokenResponse, InactiveTokenResponse, GeneralErrorResponse]:
        pass

    @abstractmethod
    async def end_session_get(
        self,
        params: Dict[str, str],
        options: APIOptions,
        session: Optional[SessionContainer],
        should_try_refresh: bool,
        user_context: Dict[str, Any],
    ) -> Union[RedirectResponse, ErrorOAuth2Response, GeneralErrorResponse]:
        pass

    @abstractmethod
    async def end_session_post(
        self,
        params: Dict[str, str],
        options: APIOptions,
        session: Optional[SessionContainer],
        should_try_refresh: bool,
        user_context: Dict[str, Any],
    ) -> Union[RedirectResponse, ErrorOAuth2Response, GeneralErrorResponse]:
        pass

    @abstractmethod
    async def logout_post(
        self,
        logout_challenge: str,
        options: APIOptions,
        session: Optional[SessionContainer],
        user_context: Dict[str, Any],
    ) -> Union[FrontendRedirectResponse, ErrorOAuth2Response, GeneralErrorResponse]:
        pass
