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

from supertokens_python.recipe.thirdparty.utils import find_right_provider

if TYPE_CHECKING:
    from supertokens_python.recipe.thirdparty.interfaces import APIOptions, APIInterface

from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python.utils import default_user_context, send_200_response


async def handle_sign_in_up_api(
    api_implementation: APIInterface, api_options: APIOptions
):
    if api_implementation.disable_sign_in_up_post:
        return None
    body = await api_options.request.json()
    if body is None:
        raise_bad_input_exception("Please provide a JSON input")

    code = body["code"] if "code" in body else ""
    auth_code_response = (
        body["authCodeResponse"] if "authCodeResponse" in body else None
    )
    client_id = body["clientId"] if "clientId" in body else None

    if "thirdPartyId" not in body or not isinstance(body["thirdPartyId"], str):
        raise_bad_input_exception("Please provide the thirdPartyId in request body")

    if not isinstance(code, str):
        raise_bad_input_exception(
            "Please make sure that the code in the request body is a string"
        )

    if code == "" and auth_code_response is None:
        raise_bad_input_exception(
            "Please provide one of code or authCodeResponse in the request body"
        )

    if auth_code_response is not None and "access_token" not in auth_code_response:
        raise_bad_input_exception(
            "Please provide the access_token inside the authCodeResponse request param"
        )

    if "redirectURI" not in body or not isinstance(body["redirectURI"], str):
        raise_bad_input_exception("Please provide the redirectURI in request body")

    third_party_id = body["thirdPartyId"]
    provider = find_right_provider(api_options.providers, third_party_id, client_id)
    if provider is None:
        if client_id is None:
            raise_bad_input_exception(
                "The third party provider "
                + third_party_id
                + " seems to be missing from the backend configs."
            )
        raise_bad_input_exception(
            "The third party provider "
            + third_party_id
            + " seems to be missing from the backend configs. If it is configured, then please make sure that you are passing the correct clientId from the frontend."
        )
    user_context = default_user_context(api_options.request)

    result = await api_implementation.sign_in_up_post(
        provider,
        code,
        body["redirectURI"],
        client_id,
        auth_code_response,
        api_options,
        user_context,
    )
    return send_200_response(result.to_json(), api_options.response)
