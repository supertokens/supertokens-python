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

from typing import Any, Dict, Optional, Union

from supertokens_python.types.response import GeneralErrorResponse

from ..interfaces import (
    APIInterface,
    APIOptions,
)
from ..types import (
    CreateLoginRequestInvalidClientError,
    CreateLoginRequestOkResult,
    VerifySAMLResponseIDPLoginDisallowedError,
    VerifySAMLResponseInvalidClientError,
    VerifySAMLResponseInvalidRelayStateError,
    VerifySAMLResponseOkResult,
    VerifySAMLResponseVerificationFailedError,
)


class APIImplementation(APIInterface):
    async def login_get(
        self,
        tenant_id: str,
        client_id: str,
        redirect_uri: str,
        state: Optional[str],
        options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[
        CreateLoginRequestOkResult,
        CreateLoginRequestInvalidClientError,
        GeneralErrorResponse,
    ]:
        # Build the ACS URL from app_info
        acs_url = (
            options.app_info.api_domain.get_as_string_dangerous()
            + options.app_info.api_base_path.get_as_string_dangerous()
            + "/saml/callback"
        )

        return await options.recipe_implementation.create_login_request(
            tenant_id=tenant_id,
            client_id=client_id,
            redirect_uri=redirect_uri,
            state=state,
            acs_url=acs_url,
            user_context=user_context,
        )

    async def callback_post(
        self,
        tenant_id: str,
        saml_response: str,
        relay_state: Optional[str],
        options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[
        VerifySAMLResponseOkResult,
        VerifySAMLResponseVerificationFailedError,
        VerifySAMLResponseInvalidRelayStateError,
        VerifySAMLResponseInvalidClientError,
        VerifySAMLResponseIDPLoginDisallowedError,
        GeneralErrorResponse,
    ]:
        return await options.recipe_implementation.verify_saml_response(
            tenant_id=tenant_id,
            saml_response=saml_response,
            relay_state=relay_state,
            user_context=user_context,
        )
