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

from typing import TYPE_CHECKING, Any, Dict

from supertokens_python.utils import send_200_response, send_non_200_response

if TYPE_CHECKING:
    from ..interfaces import (
        APIInterface,
        APIOptions,
    )


async def token_post(
    _tenant_id: str,
    api_implementation: APIInterface,
    api_options: APIOptions,
    user_context: Dict[str, Any],
):
    from ..interfaces import (
        ErrorOAuth2Response,
    )

    if api_implementation.disable_token_post is True:
        return None

    authorization_header = api_options.request.get_header("authorization")

    body = await api_options.request.get_json_or_form_data()

    response = await api_implementation.token_post(
        authorization_header=authorization_header,
        body=body,
        options=api_options,
        user_context=user_context,
    )

    if isinstance(response, ErrorOAuth2Response):
        # We do not need to normalize as this is not expected to be called by frontends where interception is enabled
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
