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
from supertokens_python.types.response import GeneralErrorResponse
from supertokens_python.utils import send_200_response

if TYPE_CHECKING:
    from ..interfaces import (
        APIInterface,
        APIOptions,
    )


async def login(
    tenant_id: str,
    api_implementation: APIInterface,
    api_options: APIOptions,
    user_context: Dict[str, Any],
) -> Optional[BaseResponse]:
    from ..types import (
        CreateLoginRequestOkResult,
    )

    if api_implementation.disable_login_get is True:
        return None

    client_id = api_options.request.get_query_param("client_id")
    redirect_uri = api_options.request.get_query_param("redirect_uri")
    state = api_options.request.get_query_param("state")

    if client_id is None:
        raise_bad_input_exception("Missing required query param: client_id")

    if redirect_uri is None:
        raise_bad_input_exception("Missing required query param: redirect_uri")

    response = await api_implementation.login_get(
        tenant_id=tenant_id,
        client_id=client_id,
        redirect_uri=redirect_uri,
        state=state,
        options=api_options,
        user_context=user_context,
    )

    if isinstance(response, CreateLoginRequestOkResult):
        return api_options.response.redirect(response.redirect_uri)

    # Per RFC 6749 §4.1.2.1: when client_id is invalid, the redirect_uri
    # cannot be validated against registered URIs, so we MUST NOT redirect
    # to the user-supplied redirect_uri (open redirect risk). Return a
    # JSON error response instead.
    if isinstance(response, GeneralErrorResponse):
        return send_200_response(response.to_json(), api_options.response)

    return send_200_response({"status": response.status}, api_options.response)
