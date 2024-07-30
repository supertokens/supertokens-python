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
from .custom import GenericProvider, NewProvider
from ..provider import (
    Provider,
    ProviderConfigForClient,
    ProviderInput,
    UserFields,
    UserInfoMap,
)


class BoxySAMLImpl(GenericProvider):
    async def get_config_for_client_type(
        self, client_type: Optional[str], user_context: Dict[str, Any]
    ) -> ProviderConfigForClient:
        config = await super().get_config_for_client_type(client_type, user_context)

        boxy_url = (
            config.additional_config.get("boxyURL")
            if config.additional_config is not None
            else None
        )
        if boxy_url:
            if config.authorization_endpoint is None:
                config.authorization_endpoint = f"{boxy_url}/api/oauth/authorize"

            if config.token_endpoint is None:
                config.token_endpoint = f"{boxy_url}/api/oauth/token"

            if config.user_info_endpoint is None:
                config.user_info_endpoint = f"{boxy_url}/api/oauth/userinfo"

        return config


def BoxySAML(input: ProviderInput) -> Provider:  # pylint: disable=redefined-builtin
    if input.config.name is None:
        input.config.name = "SAML"

    if input.config.user_info_map is None:
        input.config.user_info_map = UserInfoMap(UserFields(), UserFields())

    if input.config.user_info_map.from_user_info_api is None:
        input.config.user_info_map.from_user_info_api = UserFields()

    if input.config.user_info_map.from_user_info_api.user_id is None:
        input.config.user_info_map.from_user_info_api.user_id = "id"

    if input.config.user_info_map.from_user_info_api.email is None:
        input.config.user_info_map.from_user_info_api.email = "email"

    return NewProvider(input, BoxySAMLImpl)
