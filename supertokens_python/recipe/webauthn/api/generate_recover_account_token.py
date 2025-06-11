# Copyright (c) 2025, VRAI Labs and/or its affiliates. All rights reserved.
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

from typing import TYPE_CHECKING, Optional

from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python.framework.response import BaseResponse
from supertokens_python.types.base import UserContext
from supertokens_python.utils import send_200_response

if TYPE_CHECKING:
    from supertokens_python.recipe.webauthn.interfaces.api import (
        APIInterface,
        APIOptions,
    )


async def generate_recover_account_token_api(
    api_implementation: APIInterface,
    tenant_id: str,
    options: APIOptions,
    user_context: UserContext,
) -> Optional[BaseResponse]:
    if api_implementation.disable_generate_recover_account_token_post:
        return None

    body = await options.req.json()
    if body is None:
        raise_bad_input_exception("Please provide a JSON body")

    email = body["email"]
    if email is None or not isinstance(email, str):
        raise_bad_input_exception("Please provide the email")

    result = await api_implementation.generate_recover_account_token_post(
        email=email, tenant_id=tenant_id, options=options, user_context=user_context
    )

    return send_200_response(data_json=result.to_json(), response=options.res)
