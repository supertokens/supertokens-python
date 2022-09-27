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

from typing import TYPE_CHECKING, Callable, Optional, Awaitable

from supertokens_python.framework import BaseResponse

if TYPE_CHECKING:
    from supertokens_python.recipe.dashboard.interfaces import (
        APIOptions,
        APIInterface,
    )

from supertokens_python.utils import (
    default_user_context,
    send_non_200_response_with_message,
)


async def api_key_protector(
    api_implementation: APIInterface,
    api_options: APIOptions,
    api_function: Callable[
        [APIInterface, APIOptions], Awaitable[Optional[BaseResponse]]
    ],
) -> Optional[BaseResponse]:
    user_context = default_user_context(api_options.request)
    should_allow_access = await api_options.recipe_implementation.should_allow_access(
        api_options.request, api_options.config, user_context
    )

    if should_allow_access is False:
        return send_non_200_response_with_message(
            "Unauthorized access", 401, api_options.response
        )

    return await api_function(api_implementation, api_options)
