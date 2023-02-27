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

from ..interfaces import SignOutOK


# pylint: disable=unused-argument
async def handle_signout(
    api_implementation: APIInterface, api_options: APIOptions
) -> SignOutOK:
    if api_options.config.auth_mode == "api-key":
        send_200_response({"status": "OK"}, api_options.response)
    else:
        sessionIdFormAuthHeader = api_options.request.get_header("authorization")
        if not sessionIdFormAuthHeader:
            return raise_bad_input_exception(
                "Neither 'API Key' nor 'Authorization' header was found"
            )
        sessionIdFormAuthHeader = sessionIdFormAuthHeader.split()[1]
        response = await Querier.get_instance().send_delete_request(
            NormalisedURLPath("/recipe/dashboard/session"),
            {"sessionId": sessionIdFormAuthHeader},
        )
        send_200_response(response, api_options.response)
    return SignOutOK()
