"""
Copyright (c) 2025, VRAI Labs and/or its affiliates. All rights reserved.

This software is licensed under the Apache License, Version 2.0 (the
"License") as published by the Apache Software Foundation.

You may not use this file except in compliance with the License. You may
obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.
"""

from typing import Optional

from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python.framework.response import BaseResponse
from supertokens_python.recipe.session.asyncio import get_session
from supertokens_python.recipe.webauthn.api.implementation import APIInterface
from supertokens_python.recipe.webauthn.interfaces.api import APIOptions
from supertokens_python.types.base import UserContext
from supertokens_python.utils import send_200_response


async def list_credentials_api(
    api_implementation: APIInterface,
    tenant_id: str,
    options: APIOptions,
    user_context: UserContext,
) -> Optional[BaseResponse]:
    if api_implementation.disable_list_credentials_get:
        return None

    session = await get_session(
        request=options.req,
        session_required=True,
        override_global_claim_validators=lambda _, __, ___: [],
        user_context=user_context,
    )

    if session is None:
        raise_bad_input_exception("A valid session is required to list credentials")

    list_credentials_response = await api_implementation.list_credentials_get(
        options=options,
        user_context=user_context,
        session=session,
    )

    return send_200_response(
        data_json=list_credentials_response.to_json(), response=options.res
    )
