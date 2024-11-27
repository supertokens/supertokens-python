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

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Union
from typing_extensions import Literal
from supertokens_python.recipe.session import SessionContainer
from supertokens_python.types import APIResponse, GeneralErrorResponse, User

from .oauth2_client import OAuth2Client


if TYPE_CHECKING:
    from supertokens_python.framework import BaseRequest, BaseResponse
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

    def to_json(self):
        return {
            "status": self.status,
            "error": self.error,
            "errorDescription": self.error_description,
            "statusCode": self.status_code,
        }

    @staticmethod
    def from_json(json: Dict[str, Any]):
        return ErrorOAuth2Response(
            error=json["error"],
            error_description=json["errorDescription"],
            status_code=json["statusCode"],
        )


class ConsentRequest:
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
        return ConsentRequest(
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


class LoginRequest:
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
        return LoginRequest(
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


class TokenInfo:
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


class LoginInfo:
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


class RedirectResponse:
    def __init__(self, redirect_to: str, cookies: Optional[str] = None):
        self.redirect_to = redirect_to
        self.cookies = cookies


class GetOAuth2ClientsOkResult:
    def __init__(
        self, clients: List[OAuth2Client], next_pagination_token: Optional[str]
    ):
        self.clients = clients
        self.next_pagination_token = next_pagination_token

    @staticmethod
    def from_json(json: Dict[str, Any]):
        return GetOAuth2ClientsOkResult(
            clients=[OAuth2Client.from_json(client) for client in json["clients"]],
            next_pagination_token=json["nextPaginationToken"],
        )


class GetOAuth2ClientOkResult:
    def __init__(self, client: OAuth2Client):
        self.client = client

    @staticmethod
    def from_json(json: Dict[str, Any]):
        return GetOAuth2ClientOkResult(client=OAuth2Client.from_json(json["client"]))


class CreateOAuth2ClientOkResult:
    def __init__(self, client: OAuth2Client):
        self.client = client

    @staticmethod
    def from_json(json: Dict[str, Any]):
        return CreateOAuth2ClientOkResult(client=OAuth2Client.from_json(json["client"]))


class UpdateOAuth2ClientOkResult:
    def __init__(self, client: OAuth2Client):
        self.client = client

    @staticmethod
    def from_json(json: Dict[str, Any]):
        return UpdateOAuth2ClientOkResult(client=OAuth2Client.from_json(json["client"]))


class DeleteOAuth2ClientOkResult:
    def __init__(self):
        pass


class RecipeInterface(ABC):
    def __init__(self):
        pass

    @abstractmethod
    async def authorization(
        self,
        params: Dict[str, str],
        cookies: Optional[str],
        session: Optional[SessionContainer],
        user_context: Dict[str, Any] = {},
    ) -> Union[RedirectResponse, ErrorOAuth2Response]:
        pass

    @abstractmethod
    async def token_exchange(
        self,
        authorization_header: Optional[str],
        body: Dict[str, Optional[str]],
        user_context: Dict[str, Any] = {},
    ) -> Union[TokenInfo, ErrorOAuth2Response]:
        pass

    @abstractmethod
    async def get_consent_request(
        self, challenge: str, user_context: Dict[str, Any] = {}
    ) -> ConsentRequest:
        pass

    @abstractmethod
    async def accept_consent_request(
        self,
        challenge: str,
        context: Optional[Any] = None,
        grant_access_token_audience: Optional[List[str]] = None,
        grant_scope: Optional[List[str]] = None,
        handled_at: Optional[str] = None,
        tenant_id: str = "",
        rsub: str = "",
        session_handle: str = "",
        initial_access_token_payload: Optional[Dict[str, Any]] = None,
        initial_id_token_payload: Optional[Dict[str, Any]] = None,
        user_context: Dict[str, Any] = {},
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
    ) -> Union[LoginRequest, ErrorOAuth2Response]:
        pass

    @abstractmethod
    async def accept_login_request(
        self,
        challenge: str,
        acr: Optional[str] = None,
        amr: Optional[List[str]] = None,
        context: Optional[Any] = None,
        extend_session_lifespan: Optional[bool] = None,
        identity_provider_session_id: Optional[str] = None,
        subject: str = "",
        user_context: Dict[str, Any] = {},
    ) -> RedirectResponse:
        pass

    @abstractmethod
    async def reject_login_request(
        self,
        challenge: str,
        error: ErrorOAuth2Response,
        user_context: Dict[str, Any] = {},
    ) -> RedirectResponse:
        pass

    @abstractmethod
    async def get_oauth2_clients(
        self,
        page_size: Optional[int] = None,
        pagination_token: Optional[str] = None,
        client_name: Optional[str] = None,
        user_context: Dict[str, Any] = {},
    ) -> Union[GetOAuth2ClientsOkResult, ErrorOAuth2Response]:
        pass

    @abstractmethod
    async def get_oauth2_client(
        self,
        client_id: str,
        user_context: Dict[str, Any] = {},
    ) -> Union[GetOAuth2ClientOkResult, ErrorOAuth2Response]:
        pass

    @abstractmethod
    async def create_oauth2_client(
        self,
        user_context: Dict[str, Any] = {},
    ) -> Union[CreateOAuth2ClientOkResult, ErrorOAuth2Response]:
        pass

    @abstractmethod
    async def update_oauth2_client(
        self,
        user_context: Dict[str, Any] = {},
    ) -> Union[UpdateOAuth2ClientOkResult, ErrorOAuth2Response]:
        pass

    @abstractmethod
    async def delete_oauth2_client(
        self,
        client_id: str,
        user_context: Dict[str, Any] = {},
    ) -> Union[DeleteOAuth2ClientOkResult, ErrorOAuth2Response]:
        pass

    @abstractmethod
    async def validate_oauth2_access_token(
        self,
        token: str,
        requirements: Optional[Dict[str, Any]] = None,
        check_database: Optional[bool] = None,
        user_context: Dict[str, Any] = {},
    ) -> Dict[str, Any]:
        pass

    @abstractmethod
    async def get_requested_scopes(
        self,
        recipe_user_id: Optional[str],
        session_handle: Optional[str],
        scope_param: List[str],
        client_id: str,
        user_context: Dict[str, Any] = {},
    ) -> List[str]:
        pass

    @abstractmethod
    async def build_access_token_payload(
        self,
        user: Optional[Dict[str, Any]],
        client: OAuth2Client,
        session_handle: Optional[str],
        scopes: List[str],
        user_context: Dict[str, Any] = {},
    ) -> Dict[str, Any]:
        pass

    @abstractmethod
    async def build_id_token_payload(
        self,
        user: Optional[Dict[str, Any]],
        client: OAuth2Client,
        session_handle: Optional[str],
        scopes: List[str],
        user_context: Dict[str, Any] = {},
    ) -> Dict[str, Any]:
        pass

    @abstractmethod
    async def build_user_info(
        self,
        user: Dict[str, Any],
        access_token_payload: Dict[str, Any],
        scopes: List[str],
        tenant_id: str,
        user_context: Dict[str, Any] = {},
    ) -> Dict[str, Any]:
        pass

    @abstractmethod
    async def get_frontend_redirection_url(
        self,
        input_type: str,
        user_context: Dict[str, Any] = {},
    ) -> str:
        pass

    @abstractmethod
    async def revoke_token(
        self,
        token: str,
        authorization_header: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        user_context: Dict[str, Any] = {},
    ) -> Union[Dict[str, str], ErrorOAuth2Response]:
        pass

    @abstractmethod
    async def revoke_tokens_by_client_id(
        self,
        client_id: str,
        user_context: Dict[str, Any] = {},
    ) -> Dict[str, str]:
        pass

    @abstractmethod
    async def revoke_tokens_by_session_handle(
        self,
        session_handle: str,
        user_context: Dict[str, Any] = {},
    ) -> Dict[str, str]:
        pass

    @abstractmethod
    async def introspect_token(
        self,
        token: str,
        scopes: Optional[List[str]] = None,
        user_context: Dict[str, Any] = {},
    ) -> Dict[str, Any]:
        pass

    @abstractmethod
    async def end_session(
        self,
        params: Dict[str, str],
        session: Optional[SessionContainer] = None,
        should_try_refresh: bool = False,
        user_context: Dict[str, Any] = {},
    ) -> Union[RedirectResponse, ErrorOAuth2Response]:
        pass

    @abstractmethod
    async def accept_logout_request(
        self,
        challenge: str,
        user_context: Dict[str, Any] = {},
    ) -> Union[RedirectResponse, ErrorOAuth2Response]:
        pass

    @abstractmethod
    async def reject_logout_request(
        self,
        challenge: str,
        user_context: Dict[str, Any] = {},
    ) -> Dict[str, str]:
        pass


class APIOptions:
    def __init__(
        self,
        request: BaseRequest,
        response: BaseResponse,
        recipe_id: str,
        config: OAuth2ProviderConfig,
        recipe_implementation: RecipeInterface,
    ):
        self.request: BaseRequest = request
        self.response: BaseResponse = response
        self.recipe_id: str = recipe_id
        self.config: OAuth2ProviderConfig = config
        self.recipe_implementation: RecipeInterface = recipe_implementation


class APIInterface:
    def __init__(self):
        pass

    @abstractmethod
    async def login_get(
        self,
        login_challenge: str,
        options: APIOptions,
        session: Optional[SessionContainer] = None,
        should_try_refresh: bool = False,
        user_context: Dict[str, Any] = {},
    ) -> Union[
        Dict[str, Union[str, Optional[str]]], ErrorOAuth2Response, GeneralErrorResponse
    ]:
        pass

    @abstractmethod
    async def auth_get(
        self,
        params: Any,
        cookie: Optional[str],
        session: Optional[SessionContainer],
        should_try_refresh: bool,
        options: APIOptions,
        user_context: Dict[str, Any] = {},
    ) -> Union[
        Dict[str, Union[str, Optional[str]]], ErrorOAuth2Response, GeneralErrorResponse
    ]:
        pass

    @abstractmethod
    async def token_post(
        self,
        authorization_header: Optional[str],
        body: Any,
        options: APIOptions,
        user_context: Dict[str, Any] = {},
    ) -> Union[TokenInfo, ErrorOAuth2Response, GeneralErrorResponse]:
        pass

    @abstractmethod
    async def login_info_get(
        self,
        login_challenge: str,
        options: APIOptions,
        user_context: Dict[str, Any] = {},
    ) -> Union[
        Dict[Literal["status", "info"], Union[Literal["OK"], LoginInfo]],
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
        user_context: Dict[str, Any] = {},
    ) -> Union[Dict[str, Any], GeneralErrorResponse]:
        pass

    @abstractmethod
    async def revoke_token_post(
        self,
        token: str,
        options: APIOptions,
        user_context: Dict[str, Any] = {},
        authorization_header: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
    ) -> Union[Dict[Literal["status"], Literal["OK"]], ErrorOAuth2Response]:
        pass

    @abstractmethod
    async def introspect_token_post(
        self,
        token: str,
        scopes: Optional[List[str]],
        options: APIOptions,
        user_context: Dict[str, Any] = {},
    ) -> Union[IntrospectTokenResponse, GeneralErrorResponse]:
        pass

    @abstractmethod
    async def end_session_get(
        self,
        params: Dict[str, str],
        options: APIOptions,
        session: Optional[SessionContainer] = None,
        should_try_refresh: bool = False,
        user_context: Dict[str, Any] = {},
    ) -> Union[Dict[str, str], ErrorOAuth2Response, GeneralErrorResponse]:
        pass

    @abstractmethod
    async def end_session_post(
        self,
        params: Dict[str, str],
        options: APIOptions,
        session: Optional[SessionContainer] = None,
        should_try_refresh: bool = False,
        user_context: Dict[str, Any] = {},
    ) -> Union[Dict[str, str], ErrorOAuth2Response, GeneralErrorResponse]:
        pass

    @abstractmethod
    async def logout_post(
        self,
        logout_challenge: str,
        options: APIOptions,
        session: Optional[SessionContainer] = None,
        user_context: Dict[str, Any] = {},
    ) -> Union[
        Dict[str, Union[Literal["OK"], str]], ErrorOAuth2Response, GeneralErrorResponse
    ]:
        pass
