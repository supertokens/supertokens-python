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
from supertokens_python.exceptions import raise_bad_input_exception

from supertokens_python.framework import BaseResponse
from supertokens_python.utils import send_200_response
from supertokens_python.recipe.session.asyncio import get_session

if TYPE_CHECKING:
    from supertokens_python.recipe.totp.interfaces import APIOptions, APIInterface


async def handle_remove_device_api(
    _: str,
    api_implementation: APIInterface,
    api_options: APIOptions,
    user_context: Dict[str, Any],
) -> Union[BaseResponse, None]:
    if api_implementation.disable_remove_device_post:
        return None

    session = await get_session(
        api_options.request,
        override_global_claim_validators=lambda _, __, ___: [],
        session_required=True,
        user_context=user_context,
    )

    assert session is not None

    body = await api_options.request.json()
    if body is None:
        raise_bad_input_exception("Please provide a JSON body")
    device_name = body.get("deviceName")

    if device_name is None or not isinstance(device_name, str) or len(device_name) == 0:
        raise Exception("deviceName is required and must be a non-empty string")

    response = await api_implementation.remove_device_post(
        device_name=device_name,
        options=api_options,
        session=session,
        user_context=user_context,
    )

    return send_200_response(response.to_json(), api_options.response)
