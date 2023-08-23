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

from supertokens_python.recipe.thirdparty.types import UserInfo
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


class FacebookImpl(GenericProvider):
    async def get_config_for_client_type(
        self, client_type: Optional[str], user_context: Dict[str, Any]
    ) -> ProviderConfigForClient:
        config = await super().get_config_for_client_type(client_type, user_context)

        if config.scope is None:
            config.scope = ["email"]

        return config

    async def get_user_info(
        self, oauth_tokens: Dict[str, Any], user_context: Dict[str, Any]
    ) -> UserInfo:
        self.config.user_info_endpoint_query_params = {
            "access_token": str(oauth_tokens["access_token"]),
            "fields": "id,email",
            "format": "json",
            **(self.config.user_info_endpoint_query_params or {}),
        }
        return await super().get_user_info(oauth_tokens, user_context)


def Facebook(input: ProviderInput) -> Provider:  # pylint: disable=redefined-builtin
    if input.config.name is None:
        input.config.name = "Facebook"

    if input.config.authorization_endpoint is None:
        input.config.authorization_endpoint = (
            "https://www.facebook.com/v12.0/dialog/oauth"
        )

    if input.config.token_endpoint is None:
        input.config.token_endpoint = (
            "https://graph.facebook.com/v12.0/oauth/access_token"
        )

    if input.config.user_info_endpoint is None:
        input.config.user_info_endpoint = "https://graph.facebook.com/me"

    if input.config.user_info_map is None:
        input.config.user_info_map = UserInfoMap(UserFields(), UserFields())

    if input.config.user_info_map.from_user_info_api is None:
        input.config.user_info_map.from_user_info_api = UserFields()

    if input.config.user_info_map.from_user_info_api.user_id is None:
        input.config.user_info_map.from_user_info_api.user_id = "id"

    return NewProvider(input, FacebookImpl)
