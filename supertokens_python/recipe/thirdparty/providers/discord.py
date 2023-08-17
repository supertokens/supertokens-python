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
from ..provider import (
    Provider,
    ProviderConfigForClient,
    ProviderInput,
    UserFields,
    UserInfoMap,
)

from .custom import (
    GenericProvider,
    NewProvider,
)


class DiscordImpl(GenericProvider):
    async def get_config_for_client_type(
        self, client_type: Optional[str], user_context: Dict[str, Any]
    ) -> ProviderConfigForClient:
        config = await super().get_config_for_client_type(client_type, user_context)

        if config.scope is None:
            config.scope = ["identify", "email"]

        return config


def Discord(input: ProviderInput) -> Provider:  # pylint: disable=redefined-builtin
    if input.config.name is None:
        input.config.name = "Discord"

    if input.config.authorization_endpoint is None:
        input.config.authorization_endpoint = "https://discord.com/api/oauth2/authorize"

    if input.config.token_endpoint is None:
        input.config.token_endpoint = "https://discord.com/api/oauth2/token"

    if input.config.user_info_endpoint is None:
        input.config.user_info_endpoint = "https://discord.com/api/users/@me"

    if input.config.user_info_map is None:
        input.config.user_info_map = UserInfoMap(UserFields(), UserFields())

    if input.config.user_info_map.from_user_info_api is None:
        input.config.user_info_map.from_user_info_api = UserFields()

    if input.config.user_info_map.from_user_info_api.user_id is None:
        input.config.user_info_map.from_user_info_api.user_id = "id"

    if input.config.user_info_map.from_user_info_api.email is None:
        input.config.user_info_map.from_user_info_api.email = "email"

    if input.config.user_info_map.from_user_info_api.email_verified is None:
        input.config.user_info_map.from_user_info_api.email_verified = "verified"

    return NewProvider(input, DiscordImpl)
