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

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from supertokens_python.recipe.emailpassword.interfaces import (
        APIOptions,
        APIInterface,
    )

from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python.utils import default_user_context, send_200_response

from .utils import validate_form_fields_or_throw_error


async def handle_sign_up_api(api_implementation: APIInterface, api_options: APIOptions):
    if api_implementation.disable_sign_up_post:
        return None
    body = await api_options.request.json()
    if body is None:
        raise_bad_input_exception("Please provide a JSON body")
    form_fields_raw: Any = body["formFields"] if "formFields" in body else []
    form_fields = await validate_form_fields_or_throw_error(
        api_options.config.sign_up_feature.form_fields, form_fields_raw
    )
    user_context = default_user_context(api_options.request)

    response = await api_implementation.sign_up_post(
        form_fields, api_options, user_context
    )

    return send_200_response(response.to_json(), api_options.response)
