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

import base64
from typing import TYPE_CHECKING, Dict, Optional, Any, Union, List
from urllib.parse import parse_qs, urlparse

import jwt

from supertokens_python import AppInfo
from supertokens_python.asyncio import get_user
from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.recipe.openid.recipe import OpenIdRecipe
from supertokens_python.recipe.session.interfaces import SessionContainer
from supertokens_python.recipe.session.jwks import get_latest_keys
from supertokens_python.recipe.session.recipe import SessionRecipe
from supertokens_python.types import RecipeUserId, User

from .interfaces import (
    OAuth2TokenValidationRequirements,
    PayloadBuilderFunction,
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
    UserInfoBuilderFunction,
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
        # we handle this in the backend SDK level
        if params.get("prompt") == "none":
            params["st_prompt"] = "none"
            del params["prompt"]

        payloads = None

        if not params.get("client_id") or not isinstance(params.get("client_id"), str):
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

            user = await get_user(session.get_user_id())
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

        resp = await self.querier.send_post_request(
            NormalisedURLPath("/recipe/oauth/auth"),
            {
                "params": {**params, "scope": " ".join(scopes)},
                "iss": await OpenIdRecipe.get_issuer(user_context),
                "cookies": cookies,
                "session": payloads,
            },
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
                user_context=user_context,
                challenge=consent_request.challenge,
                grant_access_token_audience=consent_request.requested_access_token_audience,
                grant_scope=consent_request.requested_scope,
                tenant_id=session.get_tenant_id(),
                rsub=session.get_recipe_user_id().get_as_string(),
                session_handle=session.get_handle(),
                initial_access_token_payload=(
                    payloads.get("accessToken") if payloads else None
                ),
                initial_id_token_payload=payloads.get("idToken") if payloads else None,
            )

            return RedirectResponse(
                redirect_to=consent_res.redirect_to, cookies=resp["cookies"]
            )

        return RedirectResponse(redirect_to=redirect_to, cookies=resp["cookies"])

    async def token_exchange(
        self,
        authorization_header: Optional[str],
        body: Dict[str, Optional[str]],
        user_context: Dict[str, Any] = {},
    ) -> Union[TokenInfo, ErrorOAuth2Response]:
        request_body = {
            "iss": await OpenIdRecipe.get_issuer(user_context),
            "inputBody": body,
            "authorizationHeader": authorization_header,
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

            if token_info.get("active"):
                session_handle = token_info["sessionHandle"]

                client_info = await self.get_oauth2_client(
                    client_id=token_info["client_id"], user_context=user_context
                )

                if isinstance(client_info, ErrorOAuth2Response):
                    return ErrorOAuth2Response(
                        status_code=400,
                        error=client_info.error,
                        error_description=client_info.error_description,
                    )

                client = client_info.client
                user = await get_user(token_info["sub"])

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

        return TokenInfo.from_json(response)

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
        requirements: Optional[OAuth2TokenValidationRequirements] = None,
        check_database: Optional[bool] = None,
        user_context: Dict[str, Any] = {},
    ) -> Dict[str, Any]:
        # Verify token signature using session recipe's JWKS
        session_recipe = SessionRecipe.get_instance()
        matching_keys = get_latest_keys(session_recipe.config)
        payload = jwt.decode(
            token,
            matching_keys[0].key,
            algorithms=["RS256"],
            options={"verify_signature": True, "verify_exp": True},
        )

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

        return {"status": "OK", "payload": payload}

    async def get_requested_scopes(
        self,
        recipe_user_id: Optional[RecipeUserId],
        session_handle: Optional[str],
        scope_param: List[str],
        client_id: str,
        user_context: Dict[str, Any] = {},
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
        user_context: Dict[str, Any] = {},
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
        user_context: Dict[str, Any] = {},
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
        user_context: Dict[str, Any] = {},
    ) -> Dict[str, Any]:
        return await self._get_default_user_info_payload(
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
    ):
        await self.querier.send_post_request(
            NormalisedURLPath("/recipe/oauth/session/revoke"),
            {"client_id": client_id},
            user_context=user_context,
        )

    async def revoke_tokens_by_session_handle(
        self,
        session_handle: str,
        user_context: Dict[str, Any] = {},
    ):
        await self.querier.send_post_request(
            NormalisedURLPath("/recipe/oauth/session/revoke"),
            {"sessionHandle": session_handle},
            user_context=user_context,
        )

    async def introspect_token(
        self,
        token: str,
        scopes: Optional[List[str]] = None,
        user_context: Dict[str, Any] = {},
    ) -> Dict[str, Any]:
        # Determine if the token is an access token by checking if it doesn't start with "st_rt"
        is_access_token = not token.startswith("st_rt")

        # Attempt to validate the access token locally
        # If it fails, the token is not active, and we return early
        if is_access_token:
            try:
                await self.validate_oauth2_access_token(
                    token=token,
                    requirements={"scopes": scopes},
                    check_database=False,
                    user_context=user_context,
                )
            except Exception:
                return {"active": False}

        # For tokens that passed local validation or if it's a refresh token,
        # validate the token with the database by calling the core introspection endpoint
        res = await self.querier.send_post_request(
            NormalisedURLPath("/recipe/oauth/introspect"),
            {
                "token": token,
                "scope": " ".join(scopes) if scopes else None,
            },
            user_context=user_context,
        )

        return res

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
                    type="post-logout-fallback",
                    user_context=user_context,
                )
            )

        return RedirectResponse(redirect_to=redirect_to)

    async def reject_logout_request(
        self,
        challenge: str,
        user_context: Dict[str, Any] = {},
    ):
        resp = await self.querier.send_put_request(
            NormalisedURLPath("/recipe/oauth/auth/requests/logout/reject"),
            {},
            {"challenge": challenge},
            user_context=user_context,
        )

        if resp["status"] != "OK":
            raise Exception(resp["error"])
