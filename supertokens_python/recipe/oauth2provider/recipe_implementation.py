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

from supertokens_python import AppInfo
from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.recipe.openid.recipe import OpenIdRecipe
from supertokens_python.recipe.session.interfaces import SessionContainer

from .interfaces import (
    RecipeInterface,
    RedirectResponse,
    ErrorOAuth2Response,
    GetOAuth2ClientOkResult,
    GetOAuth2ClientsOkResult,
    CreateOAuth2ClientOkResult,
    UpdateOAuth2ClientOkResult,
    DeleteOAuth2ClientOkResult,
    ConsentRequest,
    LoginRequest,
    OAuth2Client,
    TokenInfo,
)


if TYPE_CHECKING:
    from supertokens_python.querier import Querier


def get_updated_redirect_to(app_info: AppInfo, redirect_to: str) -> str:
    return redirect_to.replace(
        "{apiDomain}",
        app_info.api_domain.get_as_string_dangerous()
        + app_info.api_base_path.get_as_string_dangerous(),
    )


class RecipeImplementation(RecipeInterface):
    def __init__(self, querier: Querier, app_info: AppInfo):
        super().__init__()
        self.querier = querier
        self.app_info = app_info

    async def get_login_request(
        self, challenge: str, user_context: Dict[str, Any]
    ) -> Union[LoginRequest, ErrorOAuth2Response]:
        response = await self.querier.send_get_request(
            NormalisedURLPath("/recipe/oauth/auth/requests/login"),
            {"loginChallenge": challenge},
            user_context=user_context,
        )
        if response["status"] != "OK":
            return ErrorOAuth2Response(
                response["error"],
                response["errorDescription"],
                response["statusCode"],
            )

        return LoginRequest.from_json(response)

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
        response = await self.querier.send_put_request(
            NormalisedURLPath("/recipe/oauth/auth/requests/login/accept"),
            {
                "acr": acr,
                "amr": amr,
                "context": context,
                "extendSessionLifespan": extend_session_lifespan,
                "identityProviderSessionId": identity_provider_session_id,
                "subject": subject,
            },
            {
                "loginChallenge": challenge,
            },
            user_context=user_context,
        )

        return RedirectResponse(
            redirect_to=get_updated_redirect_to(self.app_info, response["redirectTo"])
        )

    async def reject_login_request(
        self,
        challenge: str,
        error: ErrorOAuth2Response,
        user_context: Dict[str, Any] = {},
    ) -> RedirectResponse:
        response = await self.querier.send_put_request(
            NormalisedURLPath("/recipe/oauth/auth/requests/login/reject"),
            {
                "error": error.error,
                "errorDescription": error.error_description,
                "statusCode": error.status_code,
            },
            {
                "loginChallenge": challenge,
            },
            user_context=user_context,
        )
        return RedirectResponse(
            redirect_to=get_updated_redirect_to(self.app_info, response["redirectTo"])
        )

    async def get_consent_request(
        self, challenge: str, user_context: Dict[str, Any] = {}
    ) -> ConsentRequest:
        response = await self.querier.send_get_request(
            NormalisedURLPath("/recipe/oauth/auth/requests/consent"),
            {"consentChallenge": challenge},
            user_context=user_context,
        )

        return ConsentRequest.from_json(response)

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
        response = await self.querier.send_put_request(
            NormalisedURLPath("/recipe/oauth/auth/requests/consent/accept"),
            {
                "context": context,
                "grantAccessTokenAudience": grant_access_token_audience,
                "grantScope": grant_scope,
                "handledAt": handled_at,
                "iss": await OpenIdRecipe.get_issuer(user_context),
                "tId": tenant_id,
                "rsub": rsub,
                "sessionHandle": session_handle,
                "initialAccessTokenPayload": initial_access_token_payload,
                "initialIdTokenPayload": initial_id_token_payload,
            },
            {
                "consentChallenge": challenge,
            },
            user_context=user_context,
        )

        return RedirectResponse(
            redirect_to=get_updated_redirect_to(self.app_info, response["redirectTo"])
        )

    async def reject_consent_request(
        self, challenge: str, error: ErrorOAuth2Response, user_context: Dict[str, Any]
    ) -> RedirectResponse:
        response = await self.querier.send_put_request(
            NormalisedURLPath("/recipe/oauth/auth/requests/consent/reject"),
            {
                "error": error.error,
                "errorDescription": error.error_description,
                "statusCode": error.status_code,
            },
            {
                "consentChallenge": challenge,
            },
            user_context=user_context,
        )

        return RedirectResponse(
            redirect_to=get_updated_redirect_to(self.app_info, response["redirectTo"])
        )

    async def authorization(
        self,
        params: Dict[str, str],
        cookies: Optional[str],
        session: Optional[SessionContainer],
        user_context: Dict[str, Any] = {},
    ) -> Union[RedirectResponse, ErrorOAuth2Response]:
        pass

    async def token_exchange(
        self,
        authorization_header: Optional[str],
        body: Dict[str, Optional[str]],
        user_context: Dict[str, Any] = {},
    ) -> Union[TokenInfo, ErrorOAuth2Response]:
        pass

    async def get_oauth2_clients(
        self,
        page_size: Optional[int] = None,
        pagination_token: Optional[str] = None,
        client_name: Optional[str] = None,
        user_context: Dict[str, Any] = {},
    ) -> Union[GetOAuth2ClientsOkResult, ErrorOAuth2Response]:
        body: Dict[str, Any] = {}
        if page_size is not None:
            body["pageSize"] = page_size
        if pagination_token is not None:
            body["pageToken"] = pagination_token
        if client_name is not None:
            body["clientName"] = client_name

        response = await self.querier.send_get_request(
            NormalisedURLPath("/recipe/oauth/clients/list"),
            body,
            user_context=user_context,
        )

        if response["status"] == "OK":
            return GetOAuth2ClientsOkResult(
                clients=[
                    OAuth2Client.from_json(client) for client in response["clients"]
                ],
                next_pagination_token=response["nextPaginationToken"],
            )

        return ErrorOAuth2Response(
            error=response["error"],
            error_description=response["errorDescription"],
            status_code=response["statusCode"],
        )

    async def get_oauth2_client(
        self, client_id: str, user_context: Dict[str, Any] = {}
    ) -> Union[GetOAuth2ClientOkResult, ErrorOAuth2Response]:
        response = await self.querier.send_get_request(
            NormalisedURLPath("/recipe/oauth/clients"),
            {"clientId": client_id},
            user_context=user_context,
        )

        if response["status"] == "OK":
            return GetOAuth2ClientOkResult(client=OAuth2Client.from_json(response))
        elif response["status"] == "CLIENT_NOT_FOUND_ERROR":
            return ErrorOAuth2Response(
                error="invalid_request",
                error_description="The provided client_id is not valid or unknown",
            )
        else:
            return ErrorOAuth2Response(
                error=response["error"], error_description=response["errorDescription"]
            )

    async def create_oauth2_client(
        self,
        user_context: Dict[str, Any] = {},
    ) -> Union[CreateOAuth2ClientOkResult, ErrorOAuth2Response]:
        response = await self.querier.send_post_request(
            NormalisedURLPath("/recipe/oauth/clients"),
            {},  # Empty dict since no input params in function signature
            user_context=user_context,
        )

        if response["status"] == "OK":
            return CreateOAuth2ClientOkResult(client=OAuth2Client.from_json(response))
        return ErrorOAuth2Response(
            error=response["error"], error_description=response["errorDescription"]
        )

    async def update_oauth2_client(
        self,
        user_context: Dict[str, Any] = {},
    ) -> Union[UpdateOAuth2ClientOkResult, ErrorOAuth2Response]:
        response = await self.querier.send_put_request(
            NormalisedURLPath("/recipe/oauth/clients"),
            {},  # TODO update params
            None,
            user_context=user_context,
        )

        if response["status"] == "OK":
            return UpdateOAuth2ClientOkResult(client=OAuth2Client.from_json(response))
        return ErrorOAuth2Response(
            error=response["error"], error_description=response["errorDescription"]
        )

    async def delete_oauth2_client(
        self,
        client_id: str,
        user_context: Dict[str, Any] = {},
    ) -> Union[DeleteOAuth2ClientOkResult, ErrorOAuth2Response]:
        response = await self.querier.send_post_request(
            NormalisedURLPath("/recipe/oauth/clients/remove"),
            {"clientId": client_id},
            user_context=user_context,
        )

        if response["status"] == "OK":
            return DeleteOAuth2ClientOkResult()
        return ErrorOAuth2Response(
            error=response["error"], error_description=response["errorDescription"]
        )

    async def validate_oauth2_access_token(
        self,
        token: str,
        requirements: Optional[Dict[str, Any]] = None,
        check_database: Optional[bool] = None,
        user_context: Dict[str, Any] = {},
    ) -> Dict[str, Any]:
        pass

    async def get_requested_scopes(
        self,
        recipe_user_id: Optional[str],
        session_handle: Optional[str],
        scope_param: List[str],
        client_id: str,
        user_context: Dict[str, Any] = {},
    ) -> List[str]:
        return scope_param

    async def build_access_token_payload(
        self,
        client: OAuth2Client,
        scopes: List[str],
        user: Optional[Dict[str, Any]] = None,
        session_handle: Optional[str] = None,
        user_context: Dict[str, Any] = {},
    ) -> Dict[str, Any]:
        if user is None or session_handle is None:
            return {}

        return get_default_access_token_payload(
            user, scopes, session_handle, user_context
        )

    async def build_id_token_payload(
        self,
        client: OAuth2Client,
        scopes: List[str],
        user: Optional[Dict[str, Any]] = None,
        session_handle: Optional[str] = None,
        user_context: Dict[str, Any] = {},
    ) -> Dict[str, Any]:
        if user is None or session_handle is None:
            return {}

        return get_default_id_token_payload(user, scopes, session_handle, user_context)

    async def build_user_info(
        self,
        user: Dict[str, Any],
        access_token_payload: Dict[str, Any],
        scopes: List[str],
        tenant_id: str,
        user_context: Dict[str, Any] = {},
    ) -> Dict[str, Any]:
        return get_default_user_info(
            user, access_token_payload, scopes, tenant_id, user_context
        )

    async def get_frontend_redirection_url(
        self,
        input_type: str,
        user_context: Dict[str, Any] = {},
    ) -> str:
        website_domain = self.app_info.get_origin(
            None, user_context
        ).get_as_string_dangerous()
        website_base_path = self.app_info.api_base_path.get_as_string_dangerous()

    async def revoke_token(
        self,
        token: str,
        authorization_header: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        user_context: Dict[str, Any] = {},
    ) -> Union[Dict[str, str], ErrorOAuth2Response]:
        pass

    async def revoke_tokens_by_client_id(
        self,
        client_id: str,
        user_context: Dict[str, Any] = {},
    ) -> Dict[str, str]:
        pass

    async def revoke_tokens_by_session_handle(
        self,
        session_handle: str,
        user_context: Dict[str, Any] = {},
    ) -> Dict[str, str]:
        pass

    async def introspect_token(
        self,
        token: str,
        scopes: Optional[List[str]] = None,
        user_context: Dict[str, Any] = {},
    ) -> Dict[str, Any]:
        pass

    async def end_session(
        self,
        params: Dict[str, str],
        session: Optional[SessionContainer] = None,
        should_try_refresh: bool = False,
        user_context: Dict[str, Any] = {},
    ) -> Union[RedirectResponse, ErrorOAuth2Response]:
        pass

    async def accept_logout_request(
        self,
        challenge: str,
        user_context: Dict[str, Any] = {},
    ) -> Union[RedirectResponse, ErrorOAuth2Response]:
        pass

    async def reject_logout_request(
        self,
        challenge: str,
        user_context: Dict[str, Any] = {},
    ) -> Dict[str, str]:
        pass