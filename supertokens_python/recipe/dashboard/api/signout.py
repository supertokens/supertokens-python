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

from ..interfaces import SignOutOK


async def handle_emailpassword_signout_api(
    _: APIInterface,
    _tenant_id: str,
    api_options: APIOptions,
    _user_context: Dict[str, Any],
) -> SignOutOK:
    if api_options.config.auth_mode == "api-key":
        return SignOutOK()
    session_id_form_auth_header = api_options.request.get_header("authorization")
    if not session_id_form_auth_header:
        return raise_bad_input_exception(
            "Neither 'API Key' nor 'Authorization' header was found"
        )
    session_id_form_auth_header = session_id_form_auth_header.split()[1]
    await Querier.get_instance().send_delete_request(
        NormalisedURLPath("/recipe/dashboard/session"),
        {"sessionId": session_id_form_auth_header},
        user_context=_user_context,
    )
    return SignOutOK()
