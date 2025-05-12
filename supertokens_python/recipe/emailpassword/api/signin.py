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

from typing import TYPE_CHECKING, Any, Dict

from supertokens_python.auth_utils import load_session_in_auth_api_if_needed
from supertokens_python.recipe.emailpassword.interfaces import SignInPostOkResult

if TYPE_CHECKING:
    from supertokens_python.recipe.emailpassword.interfaces import (
        APIInterface,
        APIOptions,
    )

from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python.utils import (
    get_backwards_compatible_user_info,
    get_normalised_should_try_linking_with_session_user_flag,
    send_200_response,
)

from .utils import validate_form_fields_or_throw_error


async def handle_sign_in_api(
    tenant_id: str,
    api_implementation: APIInterface,
    api_options: APIOptions,
    user_context: Dict[str, Any],
):
    if api_implementation.disable_sign_in_post:
        return None
    body = await api_options.request.json()
    if body is None:
        raise_bad_input_exception("Please provide a JSON body")
    form_fields_raw: Any = body["formFields"] if "formFields" in body else []
    form_fields = await validate_form_fields_or_throw_error(
        api_options.config.sign_in_feature.form_fields, form_fields_raw, tenant_id
    )

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

    response = await api_implementation.sign_in_post(
        form_fields,
        tenant_id,
        session,
        should_try_linking_with_session_user,
        api_options,
        user_context,
    )

    if isinstance(response, SignInPostOkResult):
        return send_200_response(
            {
                "status": "OK",
                **get_backwards_compatible_user_info(
                    req=api_options.request,
                    user_info=response.user,
                    session_container=response.session,
                    created_new_recipe_user=None,
                    user_context=user_context,
                ),
            },
            api_options.response,
        )

    return send_200_response(response.to_json(), api_options.response)
