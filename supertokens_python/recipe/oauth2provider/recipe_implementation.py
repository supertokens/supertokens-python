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

from typing import TYPE_CHECKING, Dict, Optional, Any, Union, List

from .interfaces import (
    RecipeInterface,
    RedirectResponse,
    ErrorOAuth2Response,
    SessionContainer,
    GetOAuth2ClientOkResult,
    GetOAuth2ClientErrorResult,
    GetOAuth2ClientsOkResult,
    GetOAuth2ClientsErrorResult,
    CreateOAuth2ClientOkResult,
    CreateOAuth2ClientErrorResult,
    UpdateOAuth2ClientOkResult,
    UpdateOAuth2ClientErrorResult,
    DeleteOAuth2ClientOkResult,
    DeleteOAuth2ClientErrorResult,
    ConsentRequest,
    LoginRequest,
    OAuth2Client,
    TokenInfo,
)


if TYPE_CHECKING:
    from supertokens_python.querier import Querier


class RecipeImplementation(RecipeInterface):
    def __init__(self, querier: Querier):
        super().__init__()
        self.querier = querier

    async def authorization(
        self,
        params: Dict[str, str],
        cookies: Optional[str],
        session: Optional[SessionContainer],
        user_context: Optional[Dict[str, Any]] = None,
    ) -> Union[RedirectResponse, ErrorOAuth2Response]:
        pass

    async def token_exchange(
        self,
        authorization_header: Optional[str],
        body: Dict[str, Optional[str]],
        user_context: Optional[Dict[str, Any]] = None,
    ) -> Union[TokenInfo, ErrorOAuth2Response]:
        pass

    async def get_consent_request(
        self, challenge: str, user_context: Optional[Dict[str, Any]] = None
    ) -> ConsentRequest:
        pass

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
        user_context: Optional[Dict[str, Any]] = None,
    ) -> RedirectResponse:
        pass

    async def reject_consent_request(
        self, challenge: str, error: ErrorOAuth2Response, user_context: Dict[str, Any]
    ) -> RedirectResponse:
        pass

    async def get_login_request(
        self, challenge: str, user_context: Dict[str, Any]
    ) -> Union[LoginRequest, ErrorOAuth2Response]:
        pass

    async def accept_login_request(
        self,
        challenge: str,
        acr: Optional[str] = None,
        amr: Optional[List[str]] = None,
        context: Optional[Any] = None,
        extend_session_lifespan: Optional[bool] = None,
        identity_provider_session_id: Optional[str] = None,
        subject: str = "",
        user_context: Optional[Dict[str, Any]] = None,
    ) -> RedirectResponse:
        pass

    async def reject_login_request(
        self,
        challenge: str,
        error: ErrorOAuth2Response,
        user_context: Optional[Dict[str, Any]] = None,
    ) -> RedirectResponse:
        pass

    async def get_oauth2_client(
        self, client_id: str, user_context: Optional[Dict[str, Any]] = None
    ) -> Union[GetOAuth2ClientOkResult, GetOAuth2ClientErrorResult]:
        pass

    async def get_oauth2_clients(
        self,
        user_context: Optional[Dict[str, Any]] = None,
    ) -> Union[GetOAuth2ClientsOkResult, GetOAuth2ClientsErrorResult]:
        pass

    async def create_oauth2_client(
        self,
        user_context: Optional[Dict[str, Any]] = None,
    ) -> Union[CreateOAuth2ClientOkResult, CreateOAuth2ClientErrorResult]:
        pass

    async def update_oauth2_client(
        self,
        user_context: Optional[Dict[str, Any]] = None,
    ) -> Union[UpdateOAuth2ClientOkResult, UpdateOAuth2ClientErrorResult]:
        pass

    async def delete_oauth2_client(
        self,
        user_context: Optional[Dict[str, Any]] = None,
    ) -> Union[DeleteOAuth2ClientOkResult, DeleteOAuth2ClientErrorResult]:
        pass

    async def validate_oauth2_access_token(
        self,
        token: str,
        requirements: Optional[Dict[str, Any]] = None,
        check_database: Optional[bool] = None,
        user_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        pass

    async def get_requested_scopes(
        self,
        recipe_user_id: Optional[str],
        session_handle: Optional[str],
        scope_param: List[str],
        client_id: str,
        user_context: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        pass

    async def build_access_token_payload(
        self,
        user: Optional[Dict[str, Any]],
        client: OAuth2Client,
        session_handle: Optional[str],
        scopes: List[str],
        user_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        pass

    async def build_id_token_payload(
        self,
        user: Optional[Dict[str, Any]],
        client: OAuth2Client,
        session_handle: Optional[str],
        scopes: List[str],
        user_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        pass

    async def build_user_info(
        self,
        user: Dict[str, Any],
        access_token_payload: Dict[str, Any],
        scopes: List[str],
        tenant_id: str,
        user_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        pass

    async def get_frontend_redirection_url(
        self,
        input_type: str,
        user_context: Optional[Dict[str, Any]] = None,
    ) -> str:
        pass

    async def revoke_token(
        self,
        token: str,
        authorization_header: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        user_context: Optional[Dict[str, Any]] = None,
    ) -> Union[Dict[str, str], ErrorOAuth2Response]:
        pass

    async def revoke_tokens_by_client_id(
        self,
        client_id: str,
        user_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, str]:
        pass

    async def revoke_tokens_by_session_handle(
        self,
        session_handle: str,
        user_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, str]:
        pass

    async def introspect_token(
        self,
        token: str,
        scopes: Optional[List[str]] = None,
        user_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        pass

    async def end_session(
        self,
        params: Dict[str, str],
        session: Optional[SessionContainer] = None,
        should_try_refresh: bool = False,
        user_context: Optional[Dict[str, Any]] = None,
    ) -> Union[RedirectResponse, ErrorOAuth2Response]:
        pass

    async def accept_logout_request(
        self,
        challenge: str,
        user_context: Optional[Dict[str, Any]] = None,
    ) -> Union[RedirectResponse, ErrorOAuth2Response]:
        pass

    async def reject_logout_request(
        self,
        challenge: str,
        user_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, str]:
        pass
