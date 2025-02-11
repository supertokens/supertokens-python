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

from typing import TYPE_CHECKING, Any, Dict, Optional

from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python.framework import BaseResponse
from supertokens_python.utils import send_200_response, send_non_200_response

from .utils import get_session

if TYPE_CHECKING:
    from ..interfaces import (
        APIInterface,
        APIOptions,
    )


async def logout_post(
    _tenant_id: str,
    api_implementation: APIInterface,
    api_options: APIOptions,
    user_context: Dict[str, Any],
) -> Optional[BaseResponse]:
    from ..interfaces import (
        ErrorOAuth2Response,
        FrontendRedirectResponse,
    )

    if api_implementation.disable_logout_post is True:
        return None

    session = None
    try:
        session = await get_session(
            api_options.request, session_required=False, user_context=user_context
        )
    except Exception as _:
        pass

    body = await api_options.request.json()

    if body is None or "logoutChallenge" not in body:
        raise_bad_input_exception("Missing body param: logoutChallenge")

    response = await api_implementation.logout_post(
        logout_challenge=body["logoutChallenge"],
        options=api_options,
        session=session,
        user_context=user_context,
    )

    if isinstance(response, FrontendRedirectResponse):
        return send_200_response(response.to_json(), api_options.response)
    elif isinstance(response, ErrorOAuth2Response):
        # We want to avoid returning a 401 to the frontend, as it may trigger a refresh loop
        if response.status_code == 401:
            response.status_code = 400

        return send_non_200_response(
            {
                "error": response.error,
                "error_description": response.error_description,
            },
            response.status_code if response.status_code is not None else 400,
            api_options.response,
        )
    else:
        return send_200_response(response.to_json(), api_options.response)
