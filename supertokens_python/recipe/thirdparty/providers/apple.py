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

import json
from re import sub
from time import time
from typing import Any, Dict, Optional

from jwt import encode  # type: ignore

from supertokens_python.recipe.thirdparty.types import UserInfo

from ..provider import Provider, ProviderConfigForClient, ProviderInput, RedirectUriInfo
from .custom import GenericProvider, NewProvider
from .utils import (
    get_actual_client_id_from_development_client_id,
    normalise_oidc_endpoint_to_include_well_known,
)


class AppleImpl(GenericProvider):
    async def get_config_for_client_type(
        self, client_type: Optional[str], user_context: Dict[str, Any]
    ) -> ProviderConfigForClient:
        config = await super().get_config_for_client_type(client_type, user_context)

        if config.scope is None:
            config.scope = ["openid", "email"]

        if not config.client_secret:
            config.client_secret = await self._get_client_secret(config)

        if not config.oidc_discovery_endpoint:
            raise Exception("should never happen")

        # The config could be coming from core where we didn't add the well-known previously
        config.oidc_discovery_endpoint = normalise_oidc_endpoint_to_include_well_known(
            config.oidc_discovery_endpoint
        )

        return config

    async def _get_client_secret(self, config: ProviderConfigForClient) -> str:
        if (
            config.additional_config is None
            or config.additional_config.get("keyId") is None
            or config.additional_config.get("teamId") is None
            or config.additional_config.get("privateKey") is None
        ):
            raise Exception(
                "Please ensure that keyId, teamId and privateKey are provided in the additionalConfig"
            )

        payload: Dict[str, Any] = {
            "iss": config.additional_config.get("teamId"),
            "iat": time(),
            "exp": time() + (86400 * 180),  # 6 months
            "aud": "https://appleid.apple.com",
            "sub": get_actual_client_id_from_development_client_id(config.client_id),
        }
        headers = {"kid": config.additional_config.get("keyId")}
        return encode(  # type: ignore
            payload,
            sub(r"\\n", "\n", config.additional_config.get("privateKey")),  # type: ignore
            algorithm="ES256",
            headers=headers,
        )  # type: ignore

    async def exchange_auth_code_for_oauth_tokens(
        self, redirect_uri_info: RedirectUriInfo, user_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        response = await super().exchange_auth_code_for_oauth_tokens(
            redirect_uri_info, user_context
        )

        user = redirect_uri_info.redirect_uri_query_params.get("user")
        if user is not None:
            if isinstance(user, str):
                response["user"] = json.loads(user)
            elif isinstance(user, dict):
                response["user"] = user

        return response

    async def get_user_info(
        self, oauth_tokens: Dict[str, Any], user_context: Dict[str, Any]
    ) -> UserInfo:
        response = await super().get_user_info(oauth_tokens, user_context)
        user = oauth_tokens.get("user")

        user_dict: Dict[str, Any] = {}

        if user is not None:
            if isinstance(user, str):
                user_dict = json.loads(user)
            elif isinstance(user, dict):
                user_dict = user
            else:
                return response

            if response.raw_user_info_from_provider.from_id_token_payload is None:
                response.raw_user_info_from_provider.from_id_token_payload = {}

            response.raw_user_info_from_provider.from_id_token_payload["user"] = (
                user_dict
            )

        return response


def Apple(input: ProviderInput) -> Provider:  # pylint: disable=redefined-builtin
    if not input.config.name:
        input.config.name = "Apple"

    if not input.config.oidc_discovery_endpoint:
        input.config.oidc_discovery_endpoint = (
            "https://appleid.apple.com/.well-known/openid-configuration"
        )

    input.config.authorization_endpoint_query_params = {
        "response_mode": "form_post",
        **(input.config.authorization_endpoint_query_params or {}),
    }

    return NewProvider(input, AppleImpl)
