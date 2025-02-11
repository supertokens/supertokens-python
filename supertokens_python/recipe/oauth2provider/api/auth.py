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
from typing import TYPE_CHECKING, Any, Dict
from urllib.parse import parse_qsl

from dateutil import parser

from supertokens_python.utils import send_200_response, send_non_200_response

if TYPE_CHECKING:
    from ..interfaces import (
        APIInterface,
        APIOptions,
    )

from .utils import get_session


async def auth_get(
    _tenant_id: str,
    api_implementation: APIInterface,
    api_options: APIOptions,
    user_context: Dict[str, Any],
):
    from supertokens_python.recipe.session.exceptions import TryRefreshTokenError

    from ..interfaces import (
        ErrorOAuth2Response,
        RedirectResponse,
    )

    if api_implementation.disable_auth_get is True:
        return None

    original_url = api_options.request.get_original_url()
    split_url = original_url.split("?", 1)
    params = dict(parse_qsl(split_url[1], True)) if len(split_url) > 1 else {}

    session = None
    should_try_refresh = False
    try:
        session = await get_session(
            api_options.request,
            session_required=False,
            user_context=user_context,
        )
        should_try_refresh = False
    except Exception as error:
        session = None

        # should_try_refresh = False should generally not happen, but we can handle this as if the session is not present,
        # because then we redirect to the frontend, which should handle the validation error
        should_try_refresh = isinstance(error, TryRefreshTokenError)

    response = await api_implementation.auth_get(
        params=params,
        cookie=api_options.request.get_header("cookie"),
        session=session,
        should_try_refresh=should_try_refresh,
        options=api_options,
        user_context=user_context,
    )

    if isinstance(response, RedirectResponse):
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
                        samesite=morsel.get("samesite", "lax"),
                    )
        return api_options.response.redirect(response.redirect_to)
    elif isinstance(response, ErrorOAuth2Response):
        return send_non_200_response(
            {
                "error": response.error,
                "error_description": response.error_description,
            },
            response.status_code or 400,
            api_options.response,
        )
    else:
        return send_200_response(response.to_json(), api_options.response)
