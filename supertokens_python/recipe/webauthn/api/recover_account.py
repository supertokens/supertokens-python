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

from pydantic import ValidationError

from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python.framework.response import BaseResponse
from supertokens_python.recipe.webauthn.interfaces.recipe import (
    InvalidCredentialsErrorResponse,
    RegistrationPayload,
)
from supertokens_python.types.base import UserContext
from supertokens_python.utils import send_200_response

if TYPE_CHECKING:
    from supertokens_python.recipe.webauthn.interfaces.api import (
        APIInterface,
        APIOptions,
    )


async def recover_account_api(
    api_implementation: APIInterface,
    tenant_id: str,
    options: APIOptions,
    user_context: UserContext,
) -> Optional[BaseResponse]:
    if api_implementation.disable_recover_account_post:
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
        credential = RegistrationPayload.from_json(credential)
    except ValidationError:
        send_200_response(
            data_json=InvalidCredentialsErrorResponse().to_json(),
            response=options.res,
        )

    token = body["token"]
    if token is None:
        raise_bad_input_exception("Please provide the recover account token")

    if not isinstance(token, str):
        raise_bad_input_exception("The recover account token must be a string")

    result = await api_implementation.recover_account_post(
        webauthn_generated_options_id=webauthn_generated_options_id,
        credential=credential,
        token=token,
        tenant_id=tenant_id,
        options=options,
        user_context=user_context,
    )
    result_json = result.to_json()

    if result_json["status"] == "OK":
        return send_200_response(data_json={"status": "OK"}, response=options.res)

    return send_200_response(data_json=result_json, response=options.res)
