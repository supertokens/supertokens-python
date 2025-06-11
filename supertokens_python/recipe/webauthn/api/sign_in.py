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

from typing import TYPE_CHECKING, Optional, cast

from pydantic import ValidationError

from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python.framework.response import BaseResponse
from supertokens_python.recipe.webauthn.interfaces.recipe import (
    AuthenticationPayload,
    InvalidCredentialsErrorResponse,
)
from supertokens_python.types.base import UserContext
from supertokens_python.utils import (
    get_backwards_compatible_user_info,
    get_normalised_should_try_linking_with_session_user_flag,
    send_200_response,
)

if TYPE_CHECKING:
    from supertokens_python.recipe.webauthn.interfaces.api import (
        APIInterface,
        APIOptions,
    )


async def sign_in_api(
    api_implementation: APIInterface,
    tenant_id: str,
    options: APIOptions,
    user_context: UserContext,
) -> Optional[BaseResponse]:
    from supertokens_python.auth_utils import load_session_in_auth_api_if_needed
    from supertokens_python.recipe.webauthn.interfaces.api import SignInPOSTResponse

    if api_implementation.disable_sign_in_post:
        return None

    body = await options.req.json()
    if body is None:
        raise_bad_input_exception("Please provide a JSON body")

    webauthn_generated_options_id = body["webauthnGeneratedOptionsId"]
    if webauthn_generated_options_id is None:
        raise_bad_input_exception("webauthnGeneratedOptionsId is required")

    credential = body["credential"]
    if credential is None:
        raise_bad_input_exception("credential is required")

    try:
        # Try to create an object
        # If validation fails, return the response expected from the core.
        # NOTE: Can use `.construct` as an alternative, but the implementation is not stable.
        credential = AuthenticationPayload.from_json(credential)
    except ValidationError:
        send_200_response(
            data_json=InvalidCredentialsErrorResponse().to_json(),
            response=options.res,
        )

    should_try_linking_with_session_user = (
        get_normalised_should_try_linking_with_session_user_flag(
            req=options.req, body=body
        )
    )

    session = await load_session_in_auth_api_if_needed(
        request=options.req,
        should_try_linking_with_session_user=should_try_linking_with_session_user,
        user_context=user_context,
    )
    if session is not None:
        tenant_id = session.get_tenant_id()

    result = await api_implementation.sign_in_post(
        webauthn_generated_options_id=webauthn_generated_options_id,
        credential=credential,
        tenant_id=tenant_id,
        session=session,
        should_try_linking_with_session_user=should_try_linking_with_session_user,
        options=options,
        user_context=user_context,
    )
    result_json = result.to_json()

    if result_json["status"] == "OK":
        result = cast(SignInPOSTResponse, result)
        return send_200_response(
            data_json={
                "status": "OK",
                **get_backwards_compatible_user_info(
                    req=options.req,
                    user_info=result.user,
                    user_context=user_context,
                    session_container=result.session,
                    created_new_recipe_user=None,
                ),
            },
            response=options.res,
        )

    return send_200_response(data_json=result_json, response=options.res)
