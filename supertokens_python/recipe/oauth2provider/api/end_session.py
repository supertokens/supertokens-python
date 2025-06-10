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

import urllib.parse
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Dict, Optional, Union

from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python.framework import BaseResponse
from supertokens_python.types.response import GeneralErrorResponse
from supertokens_python.utils import send_200_response, send_non_200_response

from .utils import get_session

if TYPE_CHECKING:
    from supertokens_python.recipe.session import SessionContainer

    from ..interfaces import (
        APIInterface,
        APIOptions,
        ErrorOAuth2Response,
        RedirectResponse,
    )

    EndSessionCallable = Callable[
        [Dict[str, str], APIOptions, Optional[SessionContainer], bool, Dict[str, Any]],
        Awaitable[Union[RedirectResponse, ErrorOAuth2Response, GeneralErrorResponse]],
    ]


async def end_session_get(
    _tenant_id: str,
    api_implementation: APIInterface,
    api_options: APIOptions,
    user_context: Dict[str, Any],
):
    if api_implementation.disable_end_session_get is True:
        return None

    orig_url = api_options.request.get_original_url()
    split_url = orig_url.split("?", 1)
    params = (
        dict(urllib.parse.parse_qsl(split_url[1], True)) if len(split_url) > 1 else {}
    )

    return await end_session_common(
        params, api_implementation.end_session_get, api_options, user_context
    )


async def end_session_post(
    _tenant_id: str,
    api_implementation: APIInterface,
    api_options: APIOptions,
    user_context: Dict[str, Any],
):
    if api_implementation.disable_end_session_post is True:
        return None

    params = await api_options.request.get_json_or_form_data()
    if params is None:
        raise_bad_input_exception("Please provide a JSON body or form data")

    return await end_session_common(
        params, api_implementation.end_session_post, api_options, user_context
    )


async def end_session_common(
    params: Dict[str, str],
    api_implementation: Optional[EndSessionCallable],
    options: APIOptions,
    user_context: Dict[str, Any],
) -> Optional[BaseResponse]:
    from supertokens_python.recipe.session.exceptions import TryRefreshTokenError

    from ..interfaces import ErrorOAuth2Response, RedirectResponse

    if api_implementation is None:
        return None

    session = None
    should_try_refresh = False
    try:
        session = await get_session(
            options.request,
            False,
            user_context=user_context,
        )
        should_try_refresh = False
    except Exception as error:
        # We can handle this as if the session is not present, because then we redirect to the frontend,
        # which should handle the validation error
        session = None
        should_try_refresh = isinstance(error, TryRefreshTokenError)

    response = await api_implementation(
        params,
        options,
        session,
        should_try_refresh,
        user_context,
    )

    if isinstance(response, RedirectResponse):
        return options.response.redirect(response.redirect_to)
    elif isinstance(response, ErrorOAuth2Response):
        return send_non_200_response(
            {
                "error": response.error,
                "error_description": response.error_description,
            },
            response.status_code or 400,
            options.response,
        )
    else:
        if isinstance(response, dict):
            return send_200_response(response, options.response)
        else:
            return send_200_response(response.to_json(), options.response)
