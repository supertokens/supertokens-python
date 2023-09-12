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

from typing import TYPE_CHECKING, Dict, Any

if TYPE_CHECKING:
    from supertokens_python.recipe.dashboard.interfaces import (
        APIOptions,
        APIInterface,
    )

from supertokens_python.utils import (
    send_200_response,
    send_non_200_response_with_message,
)

from ..utils import validate_api_key


async def handle_validate_key_api(
    _api_implementation: APIInterface,
    api_options: APIOptions,
    user_context: Dict[str, Any],
):

    is_valid_key = await validate_api_key(
        api_options.request, api_options.config, user_context
    )

    if is_valid_key:
        return send_200_response({"status": "OK"}, api_options.response)
    return send_non_200_response_with_message("Unauthorised", 401, api_options.response)
