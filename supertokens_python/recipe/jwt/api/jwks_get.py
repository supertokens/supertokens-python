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
from typing import Any, Dict
from supertokens_python.recipe.jwt.interfaces import APIInterface, APIOptions
from supertokens_python.utils import send_200_response

from ..interfaces import JWKSGetResponse


async def jwks_get(
    api_implementation: APIInterface,
    api_options: APIOptions,
    user_context: Dict[str, Any],
):
    if api_implementation.disable_jwks_get:
        return None

    result = await api_implementation.jwks_get(api_options, user_context)

    if isinstance(result, JWKSGetResponse):
        api_options.response.set_header("Access-Control-Allow-Origin", "*")

    return send_200_response(result.to_json(), api_options.response)
