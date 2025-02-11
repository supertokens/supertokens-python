# Copyright (c) 2023, VRAI Labs and/or its affiliates. All rights reserved.
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

from supertokens_python.recipe.thirdparty.provider import (
    Provider,
    ProviderConfigForClient,
    ProviderInput,
)

from ..types import RawUserInfoFromProvider, UserInfo, UserInfoEmail
from .custom import GenericProvider, NewProvider
from .utils import do_get_request


class BitbucketImpl(GenericProvider):
    async def get_config_for_client_type(
        self, client_type: Optional[str], user_context: Dict[str, Any]
    ) -> ProviderConfigForClient:
        config = await super().get_config_for_client_type(client_type, user_context)

        if config.scope is None:
            config.scope = ["account", "email"]

        return config

    async def get_user_info(
        self, oauth_tokens: Dict[str, Any], user_context: Dict[str, Any]
    ) -> UserInfo:
        _ = user_context
        access_token = oauth_tokens.get("access_token")
        if access_token is None:
            raise Exception("Access token not found")

        headers = {
            "Authorization": f"Bearer {access_token}",
        }

        raw_user_info_from_provider = RawUserInfoFromProvider({}, {})

        user_info_from_access_token = await do_get_request(
            "https://api.bitbucket.org/2.0/user",
            query_params=None,
            headers=headers,
        )

        raw_user_info_from_provider.from_user_info_api = user_info_from_access_token

        user_info_from_email = await do_get_request(
            "https://api.bitbucket.org/2.0/user/emails",
            query_params=None,
            headers=headers,
        )

        raw_user_info_from_provider.from_user_info_api["email"] = user_info_from_email

        # Get the primary email from the Email response
        # Create an object if primary email found
        primary_email_info: UserInfoEmail | None = None
        for email_info in user_info_from_email["values"]:
            if email_info["is_primary"]:
                primary_email_info = UserInfoEmail(
                    email=email_info["email"],
                    is_verified=email_info["is_confirmed"],
                )
                break

        return UserInfo(
            third_party_user_id=raw_user_info_from_provider.from_user_info_api["uuid"],
            email=primary_email_info,
            raw_user_info_from_provider=raw_user_info_from_provider,
        )


def Bitbucket(input: ProviderInput) -> Provider:  # pylint: disable=redefined-builtin
    if not input.config.name:
        input.config.name = "Bitbucket"

    if not input.config.authorization_endpoint:
        input.config.authorization_endpoint = (
            "https://bitbucket.org/site/oauth2/authorize"
        )

    if not input.config.token_endpoint:
        input.config.token_endpoint = "https://bitbucket.org/site/oauth2/access_token"

    if input.config.authorization_endpoint_query_params is None:
        input.config.authorization_endpoint_query_params = {
            "audience": "api.atlassian.com",
        }

    return NewProvider(input, BitbucketImpl)
