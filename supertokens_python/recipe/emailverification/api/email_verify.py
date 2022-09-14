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


from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python.recipe.emailverification.interfaces import (
    APIInterface,
    APIOptions,
)
from supertokens_python.utils import (
    default_user_context,
    normalise_http_method,
    send_200_response,
)
from supertokens_python.recipe.session.asyncio import get_session


async def handle_email_verify_api(
    api_implementation: APIInterface, api_options: APIOptions
):
    user_context = default_user_context(api_options.request)
    if normalise_http_method(api_options.request.method()) == "post":
        if api_implementation.disable_email_verify_post:
            return None
        body = await api_options.request.json()
        if body is None:
            raise_bad_input_exception("Please pass JSON input body")
        if "token" not in body:
            raise_bad_input_exception("Please provide the email verification token")
        if not isinstance(body["token"], str):
            raise_bad_input_exception("The email verification token must be a string")

        token = body["token"]

        session = await get_session(
            api_options.request,
            session_required=False,
            override_global_claim_validators=lambda _, __, ___: [],
            user_context=user_context,
        )

        result = await api_implementation.email_verify_post(
            token, session, api_options, user_context
        )
    else:
        if api_implementation.disable_is_email_verified_get:
            return None

        session = await get_session(
            api_options.request,
            override_global_claim_validators=lambda _, __, ___: [],
            user_context=user_context,
        )
        assert session is not None
        result = await api_implementation.is_email_verified_get(
            session, api_options, user_context
        )

    return send_200_response(result.to_json(), api_options.response)
