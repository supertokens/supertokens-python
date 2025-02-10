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
import urllib.parse
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Union
from urllib.parse import parse_qs, urlparse

import jwt

from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.recipe.accountlinking.recipe import AccountLinkingRecipe
from supertokens_python.recipe.openid.recipe import OpenIdRecipe
from supertokens_python.recipe.session.interfaces import SessionContainer
from supertokens_python.recipe.session.jwks import get_latest_keys
from supertokens_python.recipe.session.jwt import (
    parse_jwt_without_signature_verification,
)
from supertokens_python.recipe.session.recipe import SessionRecipe
from supertokens_python.types import RecipeUserId, User

from .interfaces import (
    ActiveTokenResponse,
    ConsentRequestResponse,
    CreatedOAuth2ClientResponse,
    CreateOAuth2ClientInput,
    DeleteOAuth2ClientOkResponse,
    ErrorOAuth2Response,
    FrontendRedirectionURLTypeLogin,
    FrontendRedirectionURLTypeLogoutConfirmation,
    FrontendRedirectionURLTypePostLogoutFallback,
    FrontendRedirectionURLTypeTryRefresh,
    InactiveTokenResponse,
    LoginRequestResponse,
    OAuth2Client,
    OAuth2ClientResponse,
    OAuth2ClientsListResponse,
    OAuth2TokenValidationRequirements,
    PayloadBuilderFunction,
    RecipeInterface,
    RedirectResponse,
    RevokeTokenOkResponse,
    RevokeTokenUsingAuthorizationHeader,
    RevokeTokenUsingClientIDAndClientSecret,
    TokenInfoResponse,
    UpdatedOAuth2ClientResponse,
    UpdateOAuth2ClientInput,
    UserInfoBuilderFunction,
    ValidatedAccessTokenResponse,
)

if TYPE_CHECKING:
    from supertokens_python import AppInfo
    from supertokens_python.querier import Querier


def get_updated_redirect_to(app_info: AppInfo, redirect_to: str) -> str:
    return redirect_to.replace(
        "{apiDomain}",
        app_info.api_domain.get_as_string_dangerous()
        + app_info.api_base_path.get_as_string_dangerous(),
    )


class RecipeImplementation(RecipeInterface):
    def __init__(
        self,
        querier: Querier,
        app_info: AppInfo,
        get_default_access_token_payload: PayloadBuilderFunction,
        get_default_id_token_payload: PayloadBuilderFunction,
        get_default_user_info_payload: UserInfoBuilderFunction,
    ):
        super().__init__()
        self.querier = querier
        self.app_info = app_info
        self._get_default_access_token_payload = get_default_access_token_payload
        self._get_default_id_token_payload = get_default_id_token_payload
        self._get_default_user_info_payload = get_default_user_info_payload

    async def get_login_request(
        self, challenge: str, user_context: Dict[str, Any]
    ) -> Union[LoginRequestResponse, ErrorOAuth2Response]:
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

        return LoginRequestResponse.from_json(response)

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
        user_context: Dict[str, Any],
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
        self, challenge: str, user_context: Dict[str, Any]
    ) -> ConsentRequestResponse:
        response = await self.querier.send_get_request(
            NormalisedURLPath("/recipe/oauth/auth/requests/consent"),
            {"consentChallenge": challenge},
            user_context=user_context,
        )

        return ConsentRequestResponse.from_json(response)

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
        user_context: Dict[str, Any],
    ) -> Union[RedirectResponse, ErrorOAuth2Response]:
        # we handle this in the backend SDK level
        if params.get("prompt") == "none":
            params["st_prompt"] = "none"
            del params["prompt"]

        payloads = None

        if params.get("client_id") is None or not isinstance(
            params.get("client_id"), str
        ):
            return ErrorOAuth2Response(
                status_code=400,
                error="invalid_request",
                error_description="client_id is required and must be a string",
            )

        scopes = await self.get_requested_scopes(
            scope_param=params.get("scope", "").split() if params.get("scope") else [],
            client_id=params["client_id"],
            recipe_user_id=(
                session.get_recipe_user_id() if session is not None else None
            ),
            session_handle=session.get_handle() if session else None,
            user_context=user_context,
        )

        response_types = (
            params.get("response_type", "").split()
            if params.get("response_type")
            else []
        )

        if session is not None:
            client_info = await self.get_oauth2_client(
                client_id=params["client_id"], user_context=user_context
            )

            if isinstance(client_info, ErrorOAuth2Response):
                return ErrorOAuth2Response(
                    status_code=400,
                    error=client_info.error,
                    error_description=client_info.error_description,
                )

            client = client_info.client

            user = await AccountLinkingRecipe.get_instance().recipe_implementation.get_user(
                user_id=session.get_user_id(), user_context=user_context
            )
            if not user:
                return ErrorOAuth2Response(
                    status_code=400,
                    error="invalid_request",
                    error_description="User deleted",
                )

            # These default to empty dicts, because we want to keep them as required input
            # but they'll not be actually used in flows where we are not building them
            id_token = {}
            if "openid" in scopes and (
                "id_token" in response_types or "code" in response_types
            ):
                id_token = await self.build_id_token_payload(
                    user=user,
                    client=client,
                    session_handle=session.get_handle(),
                    scopes=scopes,
                    user_context=user_context,
                )

            access_token = {}
            if "token" in response_types or "code" in response_types:
                access_token = await self.build_access_token_payload(
                    user=user,
                    client=client,
                    session_handle=session.get_handle(),
                    scopes=scopes,
                    user_context=user_context,
                )

            payloads = {"idToken": id_token, "accessToken": access_token}

        request_body = {
            "params": {**params, "scope": " ".join(scopes)},
            "iss": await OpenIdRecipe.get_issuer(user_context),
            "session": payloads,
        }
        if cookies is not None:
            request_body["cookies"] = cookies
        resp = await self.querier.send_post_request(
            NormalisedURLPath("/recipe/oauth/auth"),
            request_body,
            user_context,
        )

        if resp["status"] == "CLIENT_NOT_FOUND_ERROR":
            return ErrorOAuth2Response(
                status_code=400,
                error="invalid_request",
                error_description="The provided client_id is not valid",
            )

        if resp["status"] != "OK":
            return ErrorOAuth2Response(
                status_code=resp["statusCode"],
                error=resp["error"],
                error_description=resp["errorDescription"],
            )

        if resp.get("redirectTo") is None:
            raise Exception(resp)
        redirect_to = get_updated_redirect_to(self.app_info, resp["redirectTo"])

        redirect_to_query_params_str = urlparse(redirect_to).query
        redirect_to_query_params: Dict[str, List[str]] = parse_qs(
            redirect_to_query_params_str
        )
        consent_challenge: Optional[str] = None

        if "consent_challenge" in redirect_to_query_params:
            if len(redirect_to_query_params["consent_challenge"]) > 0:
                consent_challenge = redirect_to_query_params["consent_challenge"][0]

        if consent_challenge is not None and session is not None:
            consent_request = await self.get_consent_request(
                challenge=consent_challenge, user_context=user_context
            )

            consent_res = await self.accept_consent_request(
                challenge=consent_request.challenge,
                context=None,
                grant_access_token_audience=consent_request.requested_access_token_audience,
                grant_scope=consent_request.requested_scope,
                handled_at=None,
                tenant_id=session.get_tenant_id(),
                rsub=session.get_recipe_user_id().get_as_string(),
                session_handle=session.get_handle(),
                initial_access_token_payload=(
                    payloads.get("accessToken") if payloads else None
                ),
                initial_id_token_payload=payloads.get("idToken") if payloads else None,
                user_context=user_context,
            )

            return RedirectResponse(
                redirect_to=consent_res.redirect_to, cookies=resp["cookies"]
            )

        return RedirectResponse(redirect_to=redirect_to, cookies=resp["cookies"])

    async def token_exchange(
        self,
        authorization_header: Optional[str],
        body: Dict[str, Optional[str]],
        user_context: Dict[str, Any],
    ) -> Union[TokenInfoResponse, ErrorOAuth2Response]:
        request_body = {
            "iss": await OpenIdRecipe.get_issuer(user_context),
            "inputBody": body,
        }

        if body.get("grant_type") == "password":
            return ErrorOAuth2Response(
                status_code=400,
                error="invalid_request",
                error_description="Unsupported grant type: password",
            )

        if body.get("grant_type") == "client_credentials":
            client_id = None
            if authorization_header:
                # Extract client_id from Basic auth header
                decoded = base64.b64decode(
                    authorization_header.replace("Basic ", "").strip()
                ).decode()
                client_id = decoded.split(":")[0]
            else:
                client_id = body.get("client_id")

            if not client_id:
                return ErrorOAuth2Response(
                    status_code=400,
                    error="invalid_request",
                    error_description="client_id is required",
                )

            scopes = str(body.get("scope", "")).split() if body.get("scope") else []

            client_info = await self.get_oauth2_client(
                client_id=client_id, user_context=user_context
            )

            if isinstance(client_info, ErrorOAuth2Response):
                return ErrorOAuth2Response(
                    status_code=400,
                    error=client_info.error,
                    error_description=client_info.error_description,
                )

            client = client_info.client
            request_body["id_token"] = await self.build_id_token_payload(
                user=None,
                client=client,
                session_handle=None,
                scopes=scopes,
                user_context=user_context,
            )
            request_body["access_token"] = await self.build_access_token_payload(
                user=None,
                client=client,
                session_handle=None,
                scopes=scopes,
                user_context=user_context,
            )

        if body.get("grant_type") == "refresh_token":
            scopes = str(body.get("scope", "")).split() if body.get("scope") else []
            token_info = await self.introspect_token(
                token=str(body["refresh_token"]),
                scopes=scopes,
                user_context=user_context,
            )

            if isinstance(token_info, ActiveTokenResponse):
                session_handle = token_info.payload["sessionHandle"]

                client_info = await self.get_oauth2_client(
                    client_id=token_info.payload["client_id"], user_context=user_context
                )

                if isinstance(client_info, ErrorOAuth2Response):
                    return ErrorOAuth2Response(
                        status_code=400,
                        error=client_info.error,
                        error_description=client_info.error_description,
                    )

                client = client_info.client
                user = await AccountLinkingRecipe.get_instance().recipe_implementation.get_user(
                    user_id=token_info.payload["sub"], user_context=user_context
                )

                if not user:
                    return ErrorOAuth2Response(
                        status_code=400,
                        error="invalid_request",
                        error_description="User not found",
                    )

                request_body["id_token"] = await self.build_id_token_payload(
                    user=user,
                    client=client,
                    session_handle=session_handle,
                    scopes=scopes,
                    user_context=user_context,
                )
                request_body["access_token"] = await self.build_access_token_payload(
                    user=user,
                    client=client,
                    session_handle=session_handle,
                    scopes=scopes,
                    user_context=user_context,
                )

        if authorization_header:
            request_body["authorizationHeader"] = authorization_header

        response = await self.querier.send_post_request(
            NormalisedURLPath("/recipe/oauth/token"),
            request_body,
            user_context=user_context,
        )

        if response["status"] == "CLIENT_NOT_FOUND_ERROR":
            return ErrorOAuth2Response(
                status_code=400,
                error="invalid_request",
                error_description="client_id not found",
            )

        if response["status"] != "OK":
            return ErrorOAuth2Response(
                status_code=response["statusCode"],
                error=response["error"],
                error_description=response["errorDescription"],
            )

        return TokenInfoResponse.from_json(response)

    async def get_oauth2_clients(
        self,
        page_size: Optional[int],
        pagination_token: Optional[str],
        client_name: Optional[str],
        user_context: Dict[str, Any],
    ) -> Union[OAuth2ClientsListResponse, ErrorOAuth2Response]:
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
            return OAuth2ClientsListResponse(
                clients=[
                    OAuth2Client.from_json(client) for client in response["clients"]
                ],
                next_pagination_token=response.get("nextPaginationToken"),
            )

        return ErrorOAuth2Response(
            error=response["error"],
            error_description=response["errorDescription"],
            status_code=response["statusCode"],
        )

    async def get_oauth2_client(
        self, client_id: str, user_context: Dict[str, Any]
    ) -> Union[OAuth2ClientResponse, ErrorOAuth2Response]:
        response = await self.querier.send_get_request(
            NormalisedURLPath("/recipe/oauth/clients"),
            {"clientId": client_id},
            user_context=user_context,
        )

        if response["status"] == "OK":
            return OAuth2ClientResponse(client=OAuth2Client.from_json(response))
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
        params: CreateOAuth2ClientInput,
        user_context: Dict[str, Any],
    ) -> Union[CreatedOAuth2ClientResponse, ErrorOAuth2Response]:
        response = await self.querier.send_post_request(
            NormalisedURLPath("/recipe/oauth/clients"),
            params.to_json(),
            user_context=user_context,
        )

        if response["status"] == "OK":
            return CreatedOAuth2ClientResponse(client=OAuth2Client.from_json(response))
        return ErrorOAuth2Response(
            error=response["error"], error_description=response["errorDescription"]
        )

    async def update_oauth2_client(
        self,
        params: UpdateOAuth2ClientInput,
        user_context: Dict[str, Any],
    ) -> Union[UpdatedOAuth2ClientResponse, ErrorOAuth2Response]:
        response = await self.querier.send_put_request(
            NormalisedURLPath("/recipe/oauth/clients"),
            params.to_json(),
            None,
            user_context=user_context,
        )

        if response["status"] == "OK":
            return UpdatedOAuth2ClientResponse(client=OAuth2Client.from_json(response))
        return ErrorOAuth2Response(
            error=response["error"], error_description=response["errorDescription"]
        )

    async def delete_oauth2_client(
        self,
        client_id: str,
        user_context: Dict[str, Any],
    ) -> Union[DeleteOAuth2ClientOkResponse, ErrorOAuth2Response]:
        response = await self.querier.send_post_request(
            NormalisedURLPath("/recipe/oauth/clients/remove"),
            {"clientId": client_id},
            user_context=user_context,
        )

        if response["status"] == "OK":
            return DeleteOAuth2ClientOkResponse()
        return ErrorOAuth2Response(
            error=response["error"], error_description=response["errorDescription"]
        )

    async def validate_oauth2_access_token(
        self,
        token: str,
        requirements: Optional[OAuth2TokenValidationRequirements],
        check_database: Optional[bool],
        user_context: Dict[str, Any],
    ) -> ValidatedAccessTokenResponse:
        access_token_obj = parse_jwt_without_signature_verification(token)

        # Verify token signature using session recipe's JWKS
        session_recipe = SessionRecipe.get_instance()
        matching_keys = get_latest_keys(session_recipe.config, access_token_obj.kid)
        err: Optional[Exception] = None

        payload: Dict[str, Any] = {}

        for matching_key in matching_keys:
            err = None
            try:
                payload = jwt.decode(
                    token,
                    matching_key.key,
                    algorithms=["RS256"],
                    options={
                        "verify_signature": True,
                        "verify_exp": True,
                        "verify_aud": False,
                    },
                )
            except Exception as e:
                err = e
                continue
            break

        if err is not None:
            raise err

        if payload.get("stt") != 1:
            raise Exception("Wrong token type")

        if requirements is not None and requirements.client_id is not None:
            if payload.get("client_id") != requirements.client_id:
                raise Exception(
                    f"The token doesn't belong to the specified client ({requirements.client_id} !== {payload.get('client_id')})"
                )

        if requirements is not None and requirements.scopes is not None:
            token_scopes = payload.get("scp", [])
            if not isinstance(token_scopes, list):
                token_scopes = [token_scopes]

            if any(scope not in token_scopes for scope in requirements.scopes):
                raise Exception("The token is missing some required scopes")

        aud = payload.get("aud", [])
        if not isinstance(aud, list):
            aud = [aud]

        if requirements is not None and requirements.audience is not None:
            if requirements.audience not in aud:
                raise Exception("The token doesn't belong to the specified audience")

        if check_database:
            response = await self.querier.send_post_request(
                NormalisedURLPath("/recipe/oauth/introspect"),
                {
                    "token": token,
                },
                user_context=user_context,
            )

            if response.get("active") is not True:
                raise Exception("The token is expired, invalid or has been revoked")

        return ValidatedAccessTokenResponse(payload=payload)

    async def get_requested_scopes(
        self,
        recipe_user_id: Optional[RecipeUserId],
        session_handle: Optional[str],
        scope_param: List[str],
        client_id: str,
        user_context: Dict[str, Any],
    ) -> List[str]:
        _ = recipe_user_id
        _ = session_handle
        _ = client_id
        _ = user_context

        return scope_param

    async def build_access_token_payload(
        self,
        user: Optional[User],
        client: OAuth2Client,
        session_handle: Optional[str],
        scopes: List[str],
        user_context: Dict[str, Any],
    ) -> Dict[str, Any]:
        if user is None or session_handle is None:
            return {}

        _ = client

        return await self._get_default_access_token_payload(
            user, scopes, session_handle, user_context
        )

    async def build_id_token_payload(
        self,
        user: Optional[User],
        client: OAuth2Client,
        session_handle: Optional[str],
        scopes: List[str],
        user_context: Dict[str, Any],
    ) -> Dict[str, Any]:
        if user is None or session_handle is None:
            return {}

        _ = client

        return await self._get_default_id_token_payload(
            user, scopes, session_handle, user_context
        )

    async def build_user_info(
        self,
        user: User,
        access_token_payload: Dict[str, Any],
        scopes: List[str],
        tenant_id: str,
        user_context: Dict[str, Any],
    ) -> Dict[str, Any]:
        return await self._get_default_user_info_payload(
            user, access_token_payload, scopes, tenant_id, user_context
        )

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
        website_domain = self.app_info.get_origin(
            None, user_context
        ).get_as_string_dangerous()
        website_base_path = self.app_info.api_base_path.get_as_string_dangerous()

        if isinstance(params, FrontendRedirectionURLTypeLogin):
            query_params: Dict[str, str] = {"loginChallenge": params.login_challenge}
            if params.tenant_id != "public":  # DEFAULT_TENANT_ID is "public"
                query_params["tenantId"] = params.tenant_id
            if params.hint is not None:
                query_params["hint"] = params.hint
            if params.force_fresh_auth:
                query_params["forceFreshAuth"] = "true"

            query_string = "&".join(
                f"{k}={urllib.parse.quote(str(v))}" for k, v in query_params.items()
            )
            return f"{website_domain}{website_base_path}?{query_string}"

        elif isinstance(params, FrontendRedirectionURLTypeTryRefresh):
            return f"{website_domain}{website_base_path}/try-refresh?loginChallenge={params.login_challenge}"

        elif isinstance(params, FrontendRedirectionURLTypePostLogoutFallback):
            return f"{website_domain}{website_base_path}"

        else:  # isinstance(params, FrontendRedirectionURLTypeLogoutConfirmation)
            return f"{website_domain}{website_base_path}/oauth/logout?logoutChallenge={params.logout_challenge}"

    async def revoke_token(
        self,
        params: Union[
            RevokeTokenUsingAuthorizationHeader,
            RevokeTokenUsingClientIDAndClientSecret,
        ],
        user_context: Dict[str, Any],
    ) -> Union[RevokeTokenOkResponse, ErrorOAuth2Response]:
        request_body = {"token": params.token}

        if isinstance(params, RevokeTokenUsingAuthorizationHeader):
            request_body["authorizationHeader"] = params.authorization_header
        else:
            request_body["client_id"] = params.client_id
            if params.client_secret is not None:
                request_body["client_secret"] = params.client_secret

        res = await self.querier.send_post_request(
            NormalisedURLPath("/recipe/oauth/token/revoke"),
            request_body,
            user_context=user_context,
        )

        if res.get("status") != "OK":
            return ErrorOAuth2Response(
                status_code=res.get("statusCode"),
                error=str(res.get("error")),
                error_description=str(res.get("errorDescription")),
            )

        return RevokeTokenOkResponse()

    async def revoke_tokens_by_client_id(
        self,
        client_id: str,
        user_context: Dict[str, Any],
    ):
        await self.querier.send_post_request(
            NormalisedURLPath("/recipe/oauth/session/revoke"),
            {"client_id": client_id},
            user_context=user_context,
        )

    async def revoke_tokens_by_session_handle(
        self,
        session_handle: str,
        user_context: Dict[str, Any],
    ):
        await self.querier.send_post_request(
            NormalisedURLPath("/recipe/oauth/session/revoke"),
            {"sessionHandle": session_handle},
            user_context=user_context,
        )

    async def introspect_token(
        self,
        token: str,
        scopes: Optional[List[str]],
        user_context: Dict[str, Any],
    ) -> Union[ActiveTokenResponse, InactiveTokenResponse]:
        # Determine if the token is an access token by checking if it doesn't start with "st_rt"
        is_access_token = not token.startswith("st_rt")

        # Attempt to validate the access token locally
        # If it fails, the token is not active, and we return early
        if is_access_token:
            try:
                await self.validate_oauth2_access_token(
                    token=token,
                    requirements=(
                        OAuth2TokenValidationRequirements(scopes=scopes)
                        if scopes
                        else None
                    ),
                    check_database=False,
                    user_context=user_context,
                )

            except Exception:
                return InactiveTokenResponse()

        # For tokens that passed local validation or if it's a refresh token,
        # validate the token with the database by calling the core introspection endpoint
        request_body = {"token": token}
        if scopes:
            request_body["scope"] = " ".join(scopes)

        res = await self.querier.send_post_request(
            NormalisedURLPath("/recipe/oauth/introspect"),
            request_body,
            user_context=user_context,
        )

        if res.get("active"):
            return ActiveTokenResponse(payload=res)
        else:
            return InactiveTokenResponse()

    async def end_session(
        self,
        params: Dict[str, str],
        should_try_refresh: bool,
        session: Optional[SessionContainer],
        user_context: Dict[str, Any],
    ) -> Union[RedirectResponse, ErrorOAuth2Response]:
        # NOTE: The API response has 3 possible cases:
        #
        # CASE 1: end_session request with a valid id_token_hint
        #        - Redirects to /oauth/logout with a logout_challenge.
        #
        # CASE 2: end_session request with an already logged out id_token_hint
        #        - Redirects to the post_logout_redirect_uri or the default logout fallback page.
        #
        # CASE 3: end_session request with a logout_verifier (after accepting the logout request)
        #        - Redirects to the post_logout_redirect_uri or the default logout fallback page.

        request_body: Dict[str, Any] = {}

        if params.get("client_id") is not None:
            request_body["clientId"] = params.get("client_id")
        if params.get("id_token_hint") is not None:
            request_body["idTokenHint"] = params.get("id_token_hint")
        if params.get("post_logout_redirect_uri") is not None:
            request_body["postLogoutRedirectUri"] = params.get(
                "post_logout_redirect_uri"
            )
        if params.get("state") is not None:
            request_body["state"] = params.get("state")
        if params.get("logout_verifier") is not None:
            request_body["logoutVerifier"] = params.get("logout_verifier")

        resp = await self.querier.send_get_request(
            NormalisedURLPath("/recipe/oauth/sessions/logout"),
            request_body,
            user_context=user_context,
        )

        if "error" in resp:
            return ErrorOAuth2Response(
                status_code=resp["statusCode"],
                error=resp["error"],
                error_description=resp["errorDescription"],
            )

        redirect_to = get_updated_redirect_to(self.app_info, resp["redirectTo"])

        initial_redirect_url = urlparse(redirect_to)
        query_params = parse_qs(initial_redirect_url.query)
        logout_challenge = query_params.get("logout_challenge", [None])[0]

        # CASE 1 (See above notes)
        if logout_challenge is not None:
            # Redirect to the frontend to ask for logout confirmation if there is a valid or expired supertokens session
            if session is not None or should_try_refresh:
                return RedirectResponse(
                    redirect_to=await self.get_frontend_redirection_url(
                        FrontendRedirectionURLTypeLogoutConfirmation(
                            logout_challenge=logout_challenge
                        ),
                        user_context=user_context,
                    )
                )
            else:
                # Accept the logout challenge immediately as there is no supertokens session
                accept_logout_response = await self.accept_logout_request(
                    challenge=logout_challenge, user_context=user_context
                )
                if isinstance(accept_logout_response, ErrorOAuth2Response):
                    return accept_logout_response
                return RedirectResponse(redirect_to=accept_logout_response.redirect_to)

        # CASE 2 or 3 (See above notes)

        # NOTE: If no post_logout_redirect_uri is provided, Hydra redirects to a fallback page.
        # In this case, we redirect the user to the /auth page.
        if redirect_to.endswith("/fallbacks/logout/callback"):
            return RedirectResponse(
                redirect_to=await self.get_frontend_redirection_url(
                    FrontendRedirectionURLTypePostLogoutFallback(),
                    user_context=user_context,
                )
            )

        return RedirectResponse(redirect_to=redirect_to)

    async def accept_logout_request(
        self,
        challenge: str,
        user_context: Dict[str, Any],
    ) -> Union[RedirectResponse, ErrorOAuth2Response]:
        resp = await self.querier.send_put_request(
            NormalisedURLPath("/recipe/oauth/auth/requests/logout/accept"),
            {"challenge": challenge},
            None,
            user_context=user_context,
        )

        if resp["status"] != "OK":
            return ErrorOAuth2Response(
                status_code=resp["statusCode"],
                error=resp["error"],
                error_description=resp["errorDescription"],
            )

        redirect_to = get_updated_redirect_to(self.app_info, resp["redirectTo"])

        if redirect_to.endswith("/fallbacks/logout/callback"):
            return RedirectResponse(
                redirect_to=await self.get_frontend_redirection_url(
                    FrontendRedirectionURLTypePostLogoutFallback(),
                    user_context=user_context,
                )
            )

        return RedirectResponse(redirect_to=redirect_to)

    async def reject_logout_request(
        self,
        challenge: str,
        user_context: Dict[str, Any],
    ):
        resp = await self.querier.send_put_request(
            NormalisedURLPath("/recipe/oauth/auth/requests/logout/reject"),
            {},
            {"challenge": challenge},
            user_context=user_context,
        )

        if resp["status"] != "OK":
            raise Exception(resp["error"])
