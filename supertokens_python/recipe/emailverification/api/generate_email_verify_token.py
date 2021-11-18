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


async def handle_generate_email_verify_token_api(api_implementation: APIInterface, api_options: APIOptions):
    if api_implementation.disable_generate_email_verify_token_post:
        return None
    result = await api_implementation.generate_email_verify_token_post(api_options)
    api_options.response.set_json_content(result.to_json())
    return api_options.response
