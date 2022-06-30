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
from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python.recipe.passwordless.interfaces import APIInterface, APIOptions
from supertokens_python.utils import default_user_context, send_200_response


async def consume_code(api_implementation: APIInterface, api_options: APIOptions):
    if api_implementation.disable_consume_code_post:
        return None

    body = await api_options.request.json()

    if body is None:
        raise_bad_input_exception("Please provide a JSON body")

    user_input_code = None
    device_id = None
    link_code = None

    if "preAuthSessionId" not in body:
        raise_bad_input_exception("Please provide preAuthSessionId")

    if "deviceId" in body or "userInputCode" in body:
        if "linkCode" in body:
            raise_bad_input_exception(
                "Please provide one of (linkCode) or (deviceId+userInputCode) and not both"
            )
        if "deviceId" not in body or "userInputCode" not in body:
            raise_bad_input_exception("Please provide both deviceId and userInputCode")
        device_id = body["deviceId"]
        user_input_code = body["userInputCode"]
    elif "linkCode" in body:
        link_code = body["linkCode"]
    else:
        raise_bad_input_exception(
            "Please provide one of (linkCode) or (deviceId+userInputCode) and not both"
        )

    pre_auth_session_id = body["preAuthSessionId"]
    user_context = default_user_context(api_options.request)

    result = await api_implementation.consume_code_post(
        pre_auth_session_id,
        user_input_code,
        device_id,
        link_code,
        api_options,
        user_context,
    )
    return send_200_response(result.to_json(), api_options.response)
