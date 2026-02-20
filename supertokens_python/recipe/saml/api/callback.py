# Copyright (c) 2024, VRAI Labs and/or its affiliates. All rights reserved.
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

from typing import TYPE_CHECKING, Any, Dict, Optional

from supertokens_python.framework import BaseResponse
from supertokens_python.types.response import GeneralErrorResponse
from supertokens_python.utils import send_200_response

if TYPE_CHECKING:
    from ..interfaces import (
        APIInterface,
        APIOptions,
    )


async def callback(
    tenant_id: str,
    api_implementation: APIInterface,
    api_options: APIOptions,
    user_context: Dict[str, Any],
) -> Optional[BaseResponse]:
    from ..types import (
        VerifySAMLResponseOkResult,
    )

    if api_implementation.disable_callback_post is True:
        return None

    # SAML callback can come as form-encoded or JSON
    body = await api_options.request.get_json_or_form_data()
    if body is None:
        body = {}

    saml_response = body.get("SAMLResponse", "")
    relay_state = body.get("RelayState")

    response = await api_implementation.callback_post(
        tenant_id=tenant_id,
        saml_response=saml_response,
        relay_state=relay_state,
        options=api_options,
        user_context=user_context,
    )

    if isinstance(response, VerifySAMLResponseOkResult):
        return api_options.response.redirect(response.redirect_uri)

    # Error case — return JSON response (matches Node SDK: send200Response)
    if isinstance(response, GeneralErrorResponse):
        return send_200_response(response.to_json(), api_options.response)

    return send_200_response({"status": response.status}, api_options.response)
