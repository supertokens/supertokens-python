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

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from supertokens_python.recipe.dashboard.interfaces import (
        APIOptions,
        APIInterface,
    )

from supertokens_python.utils import (
    default_user_context,
    send_200_response,
    send_non_200_response_with_message,
)


async def handle_validate_key_api(
    api_implementation: APIInterface, api_options: APIOptions
):
    _ = api_implementation

    should_allow_accesss = await api_options.recipe_implementation.should_allow_access(
        api_options.request,
        api_options.config,
        default_user_context(api_options.request),
    )
    if should_allow_accesss is False:
        return send_non_200_response_with_message(
            "Unauthorized access", 401, api_options.response
        )

    return send_200_response({"status": "OK"}, api_options.response)
