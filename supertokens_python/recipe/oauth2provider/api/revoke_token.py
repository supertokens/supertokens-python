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

from supertokens_python.framework import BaseResponse
from supertokens_python.utils import send_200_response, send_non_200_response

from ....types.response import GeneralErrorResponse

if TYPE_CHECKING:
    from ..interfaces import (
        APIInterface,
        APIOptions,
    )


async def revoke_token_post(
    _tenant_id: str,
    api_implementation: APIInterface,
    api_options: APIOptions,
    user_context: Dict[str, Any],
) -> Optional[BaseResponse]:
    from ..interfaces import (
        ErrorOAuth2Response,
    )

    if api_implementation.disable_revoke_token_post is True:
        return None

    body = await api_options.request.get_json_or_form_data()

    if body is None or "token" not in body:
        return send_non_200_response(
            {"message": "token is required in the request body"},
            400,
            api_options.response,
        )

    authorization_header = api_options.request.get_header("authorization")

    if authorization_header is not None and (
        "client_id" in body or "client_secret" in body
    ):
        return send_non_200_response(
            {
                "message": "Only one of authorization header or client_id and client_secret can be provided"
            },
            400,
            api_options.response,
        )

    response = await api_implementation.revoke_token_post(
        token=body["token"],
        options=api_options,
        authorization_header=authorization_header,
        client_id=body.get("client_id"),
        client_secret=body.get("client_secret"),
        user_context=user_context,
    )

    if isinstance(response, ErrorOAuth2Response):
        return send_non_200_response(
            {
                "error": response.error,
                "error_description": response.error_description,
            },
            response.status_code if response.status_code is not None else 400,
            api_options.response,
        )
    elif isinstance(response, GeneralErrorResponse):
        return send_200_response(
            response.to_json(),
            api_options.response,
        )

    return send_200_response({"status": "OK"}, api_options.response)
