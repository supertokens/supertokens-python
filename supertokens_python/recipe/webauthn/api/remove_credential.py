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

from supertokens_python.auth_utils import load_session_in_auth_api_if_needed
from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python.framework.response import BaseResponse
from supertokens_python.recipe.webauthn.interfaces.api import APIInterface, APIOptions
from supertokens_python.types.base import UserContext
from supertokens_python.utils import send_200_response


async def remove_credential_api(
    api_implementation: APIInterface,
    tenant_id: str,
    options: APIOptions,
    user_context: UserContext,
) -> Optional[BaseResponse]:
    if api_implementation.disable_remove_credential_post:
        return None

    body = await options.req.json()
    if body is None:
        raise_bad_input_exception("Please provide a JSON body")

    webauthn_credential_id = body.get("webauthnCredentialId")
    if not isinstance(webauthn_credential_id, str):
        raise_bad_input_exception("A valid webauthnCredentialId is required")

    session = await load_session_in_auth_api_if_needed(
        request=options.req,
        should_try_linking_with_session_user=None,
        user_context=user_context,
    )

    if session is None:
        raise_bad_input_exception("A valid session is required to remove a credential")

    result = await api_implementation.remove_credential_post(
        webauthn_credential_id=webauthn_credential_id,
        session=session,
        options=options,
        user_context=user_context,
    )

    return send_200_response(data_json=result.to_json(), response=options.res)
