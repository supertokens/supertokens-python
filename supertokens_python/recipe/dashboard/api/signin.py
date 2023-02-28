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
    from supertokens_python.recipe.dashboard.interfaces import APIInterface, APIOptions

from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.querier import Querier
from supertokens_python.utils import send_200_response


# pylint: disable=unused-argument
async def handle_sign_in_api(api_implementation: APIInterface, api_options: APIOptions):
    body = await api_options.request.form_data()

    if not body["email"]:
        raise_bad_input_exception("Missing required parameter 'email'")
    if not body["password"]:
        raise_bad_input_exception("Missing required parameter 'password'")
    response = await Querier.get_instance().send_post_request(
        NormalisedURLPath("/recipe/dashboard/signin"),
        {"email": body["email"], "password": body["password"]},
    )

    if "status" in response and response["status"] == "OK":
        return send_200_response(
            {"status": "OK", "sessionId": response["sessionId"]}, api_options.response
        )
    if "status" in response and response["status"] == "INVALID_CREDENTIALS_ERROR":
        return send_200_response(
            {"status": "INVALID_CREDENTIALS_ERROR", "message": response["message"]},
            api_options.response,
        )
    if "status" in response and response["status"] == "USER_SUSPENDED_ERROR":
        return send_200_response(
            {"status": "USER_SUSPENDED_ERROR", "message": response["message"]},
            api_options.response,
        )
