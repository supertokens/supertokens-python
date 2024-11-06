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

from typing import TYPE_CHECKING, Any, Dict, Union

from supertokens_python.framework import BaseResponse
from supertokens_python.utils import send_200_response
from supertokens_python.recipe.session.asyncio import get_session

if TYPE_CHECKING:
    from supertokens_python.recipe.totp.interfaces import APIOptions, APIInterface


async def handle_list_devices_api(
    _: str,
    api_implementation: APIInterface,
    api_options: APIOptions,
    user_context: Dict[str, Any],
) -> Union[BaseResponse, None]:
    if api_implementation.disable_list_devices_get:
        return None

    session = await get_session(
        api_options.request,
        override_global_claim_validators=lambda _, __, ___: [],
        session_required=True,
        user_context=user_context,
    )

    assert session is not None

    response = await api_implementation.list_devices_get(
        api_options, session, user_context
    )

    return send_200_response(response.to_json(), api_options.response)
