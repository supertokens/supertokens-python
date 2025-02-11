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

from supertokens_python.recipe.accountlinking.recipe import AccountLinkingRecipe
from supertokens_python.utils import (
    send_200_response,
    send_non_200_response_with_message,
)

if TYPE_CHECKING:
    from ..interfaces import (
        APIInterface,
        APIOptions,
    )


async def user_info_get(
    _tenant_id: str,
    api_implementation: APIInterface,
    api_options: APIOptions,
    user_context: Dict[str, Any],
):
    if api_implementation.disable_user_info_get is True:
        return None

    authorization_header = api_options.request.get_header("authorization")

    if authorization_header is None or not authorization_header.startswith("Bearer "):
        api_options.response.set_header(
            "WWW-Authenticate", 'Bearer error="invalid_token"'
        )
        api_options.response.set_header(
            "Access-Control-Expose-Headers", "WWW-Authenticate"
        )
        return send_non_200_response_with_message(
            "Missing or invalid Authorization header",
            401,
            api_options.response,
        )

    access_token = authorization_header.replace("Bearer ", "").strip()

    payload: Optional[Dict[str, Any]] = None

    try:
        payload = (
            await api_options.recipe_implementation.validate_oauth2_access_token(
                token=access_token,
                requirements=None,
                check_database=None,
                user_context=user_context,
            )
        ).payload

    except Exception:
        api_options.response.set_header(
            "WWW-Authenticate", 'Bearer error="invalid_token"'
        )
        api_options.response.set_header(
            "Access-Control-Expose-Headers", "WWW-Authenticate"
        )
        return send_non_200_response_with_message(
            "Invalid or expired OAuth2 access token",
            401,
            api_options.response,
        )

    if not isinstance(payload.get("sub"), str) or not isinstance(
        payload.get("scp"), list
    ):
        api_options.response.set_header(
            "WWW-Authenticate", 'Bearer error="invalid_token"'
        )
        api_options.response.set_header(
            "Access-Control-Expose-Headers", "WWW-Authenticate"
        )
        return send_non_200_response_with_message(
            "Malformed access token payload",
            401,
            api_options.response,
        )

    user_id = payload["sub"]

    user = await AccountLinkingRecipe.get_instance().recipe_implementation.get_user(
        user_id=user_id, user_context=user_context
    )

    if user is None:
        api_options.response.set_header(
            "WWW-Authenticate", 'Bearer error="invalid_token"'
        )
        api_options.response.set_header(
            "Access-Control-Expose-Headers", "WWW-Authenticate"
        )
        return send_non_200_response_with_message(
            "Couldn't find any user associated with the access token",
            401,
            api_options.response,
        )

    response = await api_implementation.user_info_get(
        access_token_payload=payload,
        user=user,
        tenant_id=_tenant_id,
        scopes=payload["scp"],
        options=api_options,
        user_context=user_context,
    )

    if isinstance(response, dict):
        return send_200_response(response, api_options.response)
    else:
        return send_200_response(response.to_json(), api_options.response)
