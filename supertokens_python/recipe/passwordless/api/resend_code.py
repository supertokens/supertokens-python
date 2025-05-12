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
from typing import Any, Dict

from supertokens_python.auth_utils import load_session_in_auth_api_if_needed
from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python.recipe.passwordless.interfaces import APIInterface, APIOptions
from supertokens_python.utils import (
    get_normalised_should_try_linking_with_session_user_flag,
    send_200_response,
)


async def resend_code(
    api_implementation: APIInterface,
    tenant_id: str,
    api_options: APIOptions,
    user_context: Dict[str, Any],
):
    if api_implementation.disable_resend_code_post:
        return None
    body = await api_options.request.json()

    if body is None:
        raise_bad_input_exception("Please provide a JSON body")

    if "preAuthSessionId" not in body:
        raise_bad_input_exception("Please provide preAuthSessionId")

    if "deviceId" not in body:
        raise_bad_input_exception("Please provide deviceId")

    pre_auth_session_id = body["preAuthSessionId"]
    device_id = body["deviceId"]

    should_try_linking_with_session_user = (
        get_normalised_should_try_linking_with_session_user_flag(
            api_options.request, body
        )
    )

    session = await load_session_in_auth_api_if_needed(
        api_options.request, should_try_linking_with_session_user, user_context
    )

    if session is not None:
        tenant_id = session.get_tenant_id()

    result = await api_implementation.resend_code_post(
        device_id,
        pre_auth_session_id,
        session,
        should_try_linking_with_session_user,
        tenant_id,
        api_options,
        user_context,
    )
    return send_200_response(result.to_json(), api_options.response)
