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

from supertokens_python.recipe.emailverification.interfaces import APIOptions, APIInterface

from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python.utils import normalise_http_method


async def handle_email_verify_api(api_implementation: APIInterface, api_options: APIOptions):
    if normalise_http_method(api_options.request.method()) == 'post':
        if api_implementation.disable_email_verify_post:
            return None
        body = await api_options.request.json()
        if 'token' not in body:
            raise_bad_input_exception(
                'Please provide the email verification token')
        if not isinstance(body['token'], str):
            raise_bad_input_exception(
                'The email verification token must be a string')

        token = body['token']
        result = await api_implementation.email_verify_post(token, api_options)
    else:
        if api_implementation.disable_is_email_verified_get:
            return None

        result = await api_implementation.is_email_verified_get(api_options)

    api_options.response.set_json_content(result.to_json())
    return api_options.response
