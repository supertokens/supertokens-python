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

from typing import TYPE_CHECKING, Any, Dict, List

from supertokens_python.utils import send_200_response, send_non_200_response

if TYPE_CHECKING:
    from ..interfaces import (
        APIInterface,
        APIOptions,
    )


async def introspect_token_post(
    _tenant_id: str,
    api_implementation: APIInterface,
    api_options: APIOptions,
    user_context: Dict[str, Any],
):
    if api_implementation.disable_introspect_token_post is True:
        return None

    body = await api_options.request.get_json_or_form_data()
    if body is None or "token" not in body:
        return send_non_200_response(
            {"message": "token is required in the request body"},
            400,
            api_options.response,
        )

    scopes: List[str] = body.get("scope", "").split(" ") if "scope" in body else []

    response = await api_implementation.introspect_token_post(
        body["token"],
        scopes,
        api_options,
        user_context,
    )

    return send_200_response(response.to_json(), api_options.response)
