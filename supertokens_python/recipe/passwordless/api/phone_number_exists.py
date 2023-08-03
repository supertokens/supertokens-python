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
from typing import Any, Dict
from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python.recipe.passwordless.interfaces import APIInterface, APIOptions
from supertokens_python.utils import send_200_response


async def phone_number_exists(
    api_implementation: APIInterface,
    tenant_id: str,
    api_options: APIOptions,
    user_context: Dict[str, Any],
):
    if api_implementation.disable_phone_number_exists_get:
        return None

    phone_number = api_options.request.get_query_param("phoneNumber")
    if phone_number is None:
        raise_bad_input_exception("Please provide the phoneNumber as a GET param")

    result = await api_implementation.phone_number_exists_get(
        phone_number, tenant_id, api_options, user_context
    )
    return send_200_response(result.to_json(), api_options.response)
