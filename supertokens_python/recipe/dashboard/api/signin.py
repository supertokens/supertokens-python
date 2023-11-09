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
    from supertokens_python.recipe.dashboard.interfaces import APIInterface, APIOptions

from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.querier import Querier
from supertokens_python.utils import send_200_response


async def handle_emailpassword_signin_api(
    _: APIInterface, api_options: APIOptions, _user_context: Dict[str, Any]
):
    body = await api_options.request.json()
    if body is None:
        raise_bad_input_exception("Please send body")
    email = body.get("email")
    password = body.get("password")

    if email is None or not isinstance(email, str):
        raise_bad_input_exception("Missing required parameter 'email'")
    if password is None or not isinstance(password, str):
        raise_bad_input_exception("Missing required parameter 'password'")
    response = await Querier.get_instance().send_post_request(
        NormalisedURLPath("/recipe/dashboard/signin"),
        {"email": email, "password": password},
        user_context=_user_context,
    )

    if "status" in response and response["status"] == "OK":
        return send_200_response(
            {"status": "OK", "sessionId": response["sessionId"]}, api_options.response
        )
    if "status" in response and response["status"] == "INVALID_CREDENTIALS_ERROR":
        return send_200_response(
            {"status": "INVALID_CREDENTIALS_ERROR"},
            api_options.response,
        )
    if "status" in response and response["status"] == "USER_SUSPENDED_ERROR":
        return send_200_response(
            {"status": "USER_SUSPENDED_ERROR", "message": response["message"]},
            api_options.response,
        )
