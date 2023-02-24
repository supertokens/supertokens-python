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

from typing import TYPE_CHECKING, Any, Union

if TYPE_CHECKING:
    from supertokens_python.recipe.dashboard.interfaces import (
        APIOptions,
        APIInterface,
    )

import re

from supertokens_python.exceptions import (raise_bad_input_exception,
                                           raise_general_exception)

from ..interfaces import SignInPostInvalidCredentials, SignInPostOK, SignInPostUserSuspended

VALID_EMAIL_REGEX_PATTERN = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'


async def handle_sign_in_api(api_implementation: APIInterface, api_options: APIOptions) -> Union[SignInPostOK, SignInPostInvalidCredentials, SignInPostUserSuspended]:
    body = await api_options.request.json()
    if not body:
        raise_bad_input_exception("Please provide a JSON body")
    form_fields_raw: Any = body["formFields"] if "formFields" in body else []
    # Validate input
    if len(form_fields_raw) == 0:
        raise_bad_input_exception("Please provide email and password fields")
    if re.fullmatch(VALID_EMAIL_REGEX_PATTERN, form_fields_raw["email"]):
        raise_bad_input_exception("Please provide a valid email")
    response = await api_options.recipe_implementation.sign_in(form_fields_raw["email"], form_fields_raw["password"])
    if "status" in response and response["status"] == "OK":
        return SignInPostOK(response["sessionId"])
    elif "status" in response and response["status"] == "INVALID_CREDENTIALS_ERROR":
        return SignInPostInvalidCredentials()
    elif "status" in response and response["status"] == "USER_SUSPENDED_ERROR":
        return SignInPostUserSuspended()
    else:
        raise_general_exception("Core returned invalid value")
