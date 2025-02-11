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

from supertokens_python.recipe.multitenancy.interfaces import (
    APIInterface,
    APIOptions,
)
from supertokens_python.utils import send_200_response


async def handle_login_methods_api(
    api_implementation: APIInterface,
    tenant_id: str,
    api_options: APIOptions,
    user_context: Dict[str, Any],
):
    if api_implementation.disable_login_methods_get:
        return None

    client_type = api_options.request.get_query_param("clientType")

    result = await api_implementation.login_methods_get(
        tenant_id, client_type, api_options, user_context
    )

    return send_200_response(result.to_json(), api_options.response)
