# Copyright (c) 2021, VRAI Labs and/or its affiliates. All rights reserved.
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

from typing import TYPE_CHECKING, Any, Awaitable, Callable, Dict, Optional

from supertokens_python.framework import BaseResponse

if TYPE_CHECKING:
    from supertokens_python.recipe.dashboard.interfaces import (
        APIInterface,
        APIOptions,
    )
    from supertokens_python.types import APIResponse

from supertokens_python.utils import (
    send_200_response,
    send_non_200_response_with_message,
)

from ..exceptions import DashboardOperationNotAllowedError


async def api_key_protector(
    api_implementation: APIInterface,
    tenant_id: str,
    api_options: APIOptions,
    api_function: Callable[
        [APIInterface, str, APIOptions, Dict[str, Any]], Awaitable[APIResponse]
    ],
    user_context: Dict[str, Any],
) -> Optional[BaseResponse]:
    should_allow_access = False

    try:
        should_allow_access = (
            await api_options.recipe_implementation.should_allow_access(
                api_options.request, api_options.config, user_context
            )
        )
    except DashboardOperationNotAllowedError as _:
        return send_non_200_response_with_message(
            "You are not permitted to perform this operation",
            403,
            api_options.response,
        )

    if should_allow_access is False:
        return send_non_200_response_with_message(
            "Unauthorised access", 401, api_options.response
        )

    response = await api_function(
        api_implementation, tenant_id, api_options, user_context
    )
    return send_200_response(response.to_json(), api_options.response)
