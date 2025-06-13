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

from typing import Any, Dict, List, Optional, Union

from supertokens_python.recipe.session import SessionContainer
from supertokens_python.types import User
from supertokens_python.types.response import GeneralErrorResponse

from ..interfaces import (
    ActiveTokenResponse,
    APIInterface,
    APIOptions,
    ErrorOAuth2Response,
    FrontendRedirectResponse,
    InactiveTokenResponse,
    LoginInfoResponse,
    RedirectResponse,
    RevokeTokenOkResponse,
    RevokeTokenUsingAuthorizationHeader,
    RevokeTokenUsingClientIDAndClientSecret,
    TokenInfoResponse,
    UserInfoResponse,
)
from .utils import (
    handle_login_internal_redirects,
    handle_logout_internal_redirects,
    login_get,
)


class APIImplementation(APIInterface):
    async def login_get(
        self,
        login_challenge: str,
        options: APIOptions,
        session: Optional[SessionContainer],
        should_try_refresh: bool,
        user_context: Dict[str, Any],
    ) -> Union[FrontendRedirectResponse, ErrorOAuth2Response, GeneralErrorResponse]:
        response = await login_get(
            recipe_implementation=options.recipe_implementation,
            login_challenge=login_challenge,
            session=session,
            should_try_refresh=should_try_refresh,
            is_direct_call=True,
            cookies=None,
            user_context=user_context,
        )

        if isinstance(response, ErrorOAuth2Response):
            return response

        resp_after_internal_redirects = await handle_login_internal_redirects(
            app_info=options.app_info,
            response=response,
            cookie=options.request.get_header("cookie") or "",
            recipe_implementation=options.recipe_implementation,
            session=session,
            should_try_refresh=should_try_refresh,
            user_context=user_context,
        )

        if isinstance(resp_after_internal_redirects, ErrorOAuth2Response):
            return resp_after_internal_redirects

        return FrontendRedirectResponse(
            frontend_redirect_to=resp_after_internal_redirects.redirect_to,
            cookies=resp_after_internal_redirects.cookies,
        )

    async def auth_get(
        self,
        params: Any,
        cookie: Optional[str],
        session: Optional[SessionContainer],
        should_try_refresh: bool,
        options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[RedirectResponse, ErrorOAuth2Response, GeneralErrorResponse]:
        response = await options.recipe_implementation.authorization(
            params=params,
            cookies=cookie,
            session=session,
            user_context=user_context,
        )

        if isinstance(response, ErrorOAuth2Response):
            return response

        return await handle_login_internal_redirects(
            app_info=options.app_info,
            response=response,
            recipe_implementation=options.recipe_implementation,
            cookie=cookie or "",
            session=session,
            should_try_refresh=should_try_refresh,
            user_context=user_context,
        )

    async def token_post(
        self,
        authorization_header: Optional[str],
        body: Any,
        options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[TokenInfoResponse, ErrorOAuth2Response, GeneralErrorResponse]:
        return await options.recipe_implementation.token_exchange(
            authorization_header=authorization_header,
            body=body,
            user_context=user_context,
        )

    async def login_info_get(
        self,
        login_challenge: str,
        options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[LoginInfoResponse, ErrorOAuth2Response, GeneralErrorResponse]:
        login_res = await options.recipe_implementation.get_login_request(
            challenge=login_challenge,
            user_context=user_context,
        )

        if isinstance(login_res, ErrorOAuth2Response):
            return login_res

        client = login_res.client

        return LoginInfoResponse(
            client_id=client.client_id,
            client_name=client.client_name,
            tos_uri=client.tos_uri,
            policy_uri=client.policy_uri,
            logo_uri=client.logo_uri,
            client_uri=client.client_uri,
            metadata=client.metadata,
        )

    async def user_info_get(
        self,
        access_token_payload: Dict[str, Any],
        user: User,
        scopes: List[str],
        tenant_id: str,
        options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[UserInfoResponse, GeneralErrorResponse]:
        return UserInfoResponse(
            await options.recipe_implementation.build_user_info(
                user=user,
                access_token_payload=access_token_payload,
                scopes=scopes,
                tenant_id=tenant_id,
                user_context=user_context,
            )
        )

    async def revoke_token_post(
        self,
        options: APIOptions,
        token: str,
        authorization_header: Optional[str],
        client_id: Optional[str],
        client_secret: Optional[str],
        user_context: Dict[str, Any],
    ) -> Union[RevokeTokenOkResponse, ErrorOAuth2Response, GeneralErrorResponse]:
        if authorization_header is not None:
            return await options.recipe_implementation.revoke_token(
                params=RevokeTokenUsingAuthorizationHeader(
                    token=token,
                    authorization_header=authorization_header,
                ),
                user_context=user_context,
            )
        elif client_id is not None:
            if client_secret is None:
                raise Exception("client_secret is required")

            return await options.recipe_implementation.revoke_token(
                params=RevokeTokenUsingClientIDAndClientSecret(
                    token=token,
                    client_id=client_id,
                    client_secret=client_secret,
                ),
                user_context=user_context,
            )
        else:
            raise Exception(
                "Either of 'authorization_header' or 'client_id' must be provided"
            )

    async def introspect_token_post(
        self,
        token: str,
        scopes: Optional[List[str]],
        options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[ActiveTokenResponse, InactiveTokenResponse, GeneralErrorResponse]:
        return await options.recipe_implementation.introspect_token(
            token=token,
            scopes=scopes,
            user_context=user_context,
        )

    async def end_session_get(
        self,
        params: Dict[str, str],
        options: APIOptions,
        session: Optional[SessionContainer],
        should_try_refresh: bool,
        user_context: Dict[str, Any],
    ) -> Union[RedirectResponse, ErrorOAuth2Response, GeneralErrorResponse]:
        response = await options.recipe_implementation.end_session(
            params=params,
            session=session,
            should_try_refresh=should_try_refresh,
            user_context=user_context,
        )

        if isinstance(response, ErrorOAuth2Response):
            return response

        return await handle_logout_internal_redirects(
            app_info=options.app_info,
            response=response,
            session=session,
            recipe_implementation=options.recipe_implementation,
            user_context=user_context,
        )

    async def end_session_post(
        self,
        params: Dict[str, str],
        options: APIOptions,
        session: Optional[SessionContainer],
        should_try_refresh: bool,
        user_context: Dict[str, Any],
    ) -> Union[RedirectResponse, ErrorOAuth2Response, GeneralErrorResponse]:
        response = await options.recipe_implementation.end_session(
            params=params,
            session=session,
            should_try_refresh=should_try_refresh,
            user_context=user_context,
        )

        if isinstance(response, ErrorOAuth2Response):
            return response

        return await handle_logout_internal_redirects(
            app_info=options.app_info,
            response=response,
            session=session,
            recipe_implementation=options.recipe_implementation,
            user_context=user_context,
        )

    async def logout_post(
        self,
        logout_challenge: str,
        options: APIOptions,
        session: Optional[SessionContainer],
        user_context: Dict[str, Any],
    ) -> Union[FrontendRedirectResponse, ErrorOAuth2Response, GeneralErrorResponse]:
        if session is not None:
            await session.revoke_session(user_context)

        response = await options.recipe_implementation.accept_logout_request(
            challenge=logout_challenge,
            user_context=user_context,
        )

        if isinstance(response, ErrorOAuth2Response):
            return response

        res = await handle_logout_internal_redirects(
            app_info=options.app_info,
            response=response,
            recipe_implementation=options.recipe_implementation,
            session=session,
            user_context=user_context,
        )

        if isinstance(res, ErrorOAuth2Response):
            return res

        return FrontendRedirectResponse(frontend_redirect_to=res.redirect_to)
