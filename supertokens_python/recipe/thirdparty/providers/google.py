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
from typing import Any, Callable, Dict, Optional

from ..provider import (
    Provider,
    ProviderConfig,
    ProviderConfigForClient,
    ProviderInput,
    UserFields,
    UserInfoMap,
)

from .custom import (
    GenericProvider,
    NewProvider,
)


class GoogleImpl(GenericProvider):
    async def get_config_for_client_type(
        self, client_type: Optional[str], user_context: Dict[str, Any]
    ) -> ProviderConfigForClient:
        config = await super().get_config_for_client_type(client_type, user_context)

        if config.scope is None:
            config.scope = ["openid", "email"]

        return config


def Google(
    input: ProviderInput,  # pylint: disable=redefined-builtin
    base_class: Callable[[ProviderConfig], GoogleImpl] = GoogleImpl,
) -> Provider:
    if input.config.name is None:
        input.config.name = "Google"

    if input.config.oidc_discovery_endpoint is None:
        input.config.oidc_discovery_endpoint = "https://accounts.google.com/"

    if input.config.user_info_map is None:
        input.config.user_info_map = UserInfoMap(UserFields(), UserFields())

    if input.config.authorization_endpoint_query_params is None:
        input.config.authorization_endpoint_query_params = {}

    input.config.authorization_endpoint_query_params = {
        "included_grant_scopes": "true",
        "access_type": "offline",
        **input.config.authorization_endpoint_query_params,
    }

    return NewProvider(input, base_class)
