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

from http.cookies import SimpleCookie
from typing import TYPE_CHECKING, Any, Dict, Optional

from dateutil import parser

from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python.framework import BaseResponse
from supertokens_python.utils import send_200_response, send_non_200_response

from .utils import get_session

if TYPE_CHECKING:
    from ..interfaces import (
        APIInterface,
        APIOptions,
    )


async def login(
    _tenant_id: str,
    api_implementation: APIInterface,
    api_options: APIOptions,
    user_context: Dict[str, Any],
) -> Optional[BaseResponse]:
    from supertokens_python.recipe.session.exceptions import TryRefreshTokenError

    from ..interfaces import (
        ErrorOAuth2Response,
        FrontendRedirectResponse,
    )

    if api_implementation.disable_login_get is True:
        return None

    session = None
    should_try_refresh = False
    try:
        session = await get_session(
            api_options.request,
            False,
            user_context=user_context,
        )
        should_try_refresh = False
    except Exception as error:
        # We can handle this as if the session is not present, because then we redirect to the frontend,
        # which should handle the validation error
        session = None
        should_try_refresh = isinstance(error, TryRefreshTokenError)

    login_challenge = api_options.request.get_query_param(
        "login_challenge"
    ) or api_options.request.get_query_param("loginChallenge")
    if login_challenge is None:
        raise_bad_input_exception("Missing input param: loginChallenge")

    response = await api_implementation.login_get(
        login_challenge=login_challenge,
        options=api_options,
        session=session,
        should_try_refresh=should_try_refresh,
        user_context=user_context,
    )

    if isinstance(response, FrontendRedirectResponse):
        if response.cookies:
            for cookie_string in response.cookies:
                cookie = SimpleCookie()
                cookie.load(cookie_string)
                for morsel in cookie.values():
                    api_options.response.set_cookie(
                        key=morsel.key,
                        value=morsel.value,
                        domain=morsel.get("domain"),
                        secure=morsel.get("secure", True),
                        httponly=morsel.get("httponly", True),
                        expires=parser.parse(morsel.get("expires", "")).timestamp()
                        * 1000,  # type: ignore
                        path=morsel.get("path", "/"),
                        samesite=morsel.get("samesite", "lax").lower(),
                    )

        return send_200_response(
            {"frontendRedirectTo": response.frontend_redirect_to},
            api_options.response,
        )

    elif isinstance(response, ErrorOAuth2Response):
        # We want to avoid returning a 401 to the frontend, as it may trigger a refresh loop
        if response.status_code == 401:
            response.status_code = 400

        return send_non_200_response(
            {
                "error": response.error,
                "error_description": response.error_description,
            },
            response.status_code or 400,
            api_options.response,
        )

    return send_200_response(response.to_json(), api_options.response)
