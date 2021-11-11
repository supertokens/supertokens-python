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
    from supertokens_python.recipe.thirdparty.interfaces import APIOptions, APIInterface


async def handle_apple_redirect_api(api_implementation: APIInterface, api_options: APIOptions):
    if api_implementation.disable_apple_redirect_handler_post:
        return None
    body = await api_options.request.form_data()

    code = body['code'] if 'code' in body else ""
    state = body['state'] if 'state' in body else ""

    # this will redirect the user...
    await api_implementation.apple_redirect_handler_post(code, state, api_options)

    return api_options.response
