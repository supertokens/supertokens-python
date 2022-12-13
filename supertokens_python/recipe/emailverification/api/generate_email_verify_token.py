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

from supertokens_python.recipe.emailverification.interfaces import (
    APIInterface,
    APIOptions,
)
from supertokens_python.utils import default_user_context, send_200_response
from supertokens_python.recipe.session.asyncio import get_session


async def handle_generate_email_verify_token_api(
    api_implementation: APIInterface, api_options: APIOptions
):
    if api_implementation.disable_generate_email_verify_token_post:
        return None
    user_context = default_user_context(api_options.request)
    session = await get_session(
        api_options.request,
        override_global_claim_validators=lambda _, __, ___: [],
        user_context=user_context,
    )
    assert session is not None

    result = await api_implementation.generate_email_verify_token_post(
        session, api_options, user_context
    )
    return send_200_response(result.to_json(), api_options.response)
