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
from typing import Any, Dict, Optional

from .google import Google, GoogleImpl

from ..provider import (
    Provider,
    ProviderConfigForClient,
    ProviderInput,
)


class GoogleWorkspacesImpl(GoogleImpl):
    async def get_config_for_client_type(
        self, client_type: Optional[str], user_context: Dict[str, Any]
    ) -> ProviderConfigForClient:
        config = await super().get_config_for_client_type(client_type, user_context)

        if config.additional_config is None:
            config.additional_config = {}

        config.authorization_endpoint_query_params = {
            "hd": str(config.additional_config.get("hd", "*")),
            **(config.authorization_endpoint_query_params or {}),
        }

        return config


def GoogleWorkspaces(
    input: ProviderInput,  # pylint: disable=redefined-builtin
) -> Provider:
    if input.config.name is None:
        input.config.name = "Google Workspaces"

    if input.config.validate_id_token_payload is None:

        async def default_validate_id_token_payload(
            id_token_payload: Dict[str, Any],
            config: ProviderConfigForClient,
            _user_context: Dict[str, Any],
        ):
            if (config.additional_config or {}).get("hd", "*") != "*":
                if (config.additional_config or {}).get("hd") != id_token_payload.get(
                    "hd"
                ):
                    raise Exception(
                        "the value for hd claim in the id token does not match the value provided in the config"
                    )

        input.config.validate_id_token_payload = default_validate_id_token_payload

    return Google(input, GoogleWorkspacesImpl)
