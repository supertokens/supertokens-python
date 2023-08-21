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

from typing import Any, Dict, Optional, Union
from supertokens_python.recipe.thirdparty.providers.utils import do_get_request

from supertokens_python.recipe.thirdparty.types import (
    RawUserInfoFromProvider,
    UserInfo,
    UserInfoEmail,
)
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


class LinkedinImpl(GenericProvider):
    async def get_config_for_client_type(
        self, client_type: Optional[str], user_context: Dict[str, Any]
    ) -> ProviderConfigForClient:
        config = await super().get_config_for_client_type(client_type, user_context)

        if config.scope is None:
            config.scope = ["r_emailaddress", "r_liteprofile"]

        return config

    async def get_user_info(
        self, oauth_tokens: Dict[str, Any], user_context: Dict[str, Any]
    ) -> UserInfo:
        access_token: Union[str, None] = oauth_tokens.get("access_token")

        if access_token is None:
            raise Exception("Access token not found")

        headers = {
            "Authorization": f"Bearer {access_token}",
        }

        raw_user_info_from_provider = RawUserInfoFromProvider({}, {})
        user_info = await do_get_request(
            "https://api.linkedin.com/v2/me", headers=headers
        )
        raw_user_info_from_provider.from_user_info_api = user_info

        email_api_url = "https://api.linkedin.com/v2/emailAddress"
        email_info: Dict[str, Any] = await do_get_request(
            email_api_url,
            query_params={"q": "members", "projection": "(elements*(handle~))"},
            headers=headers,
        )

        if email_info.get("elements") is not None and len(email_info.get("elements")) > 0:  # type: ignore
            raw_user_info_from_provider.from_user_info_api["email"] = email_info.get("elements")[0].get("handle~").get("emailAddress")  # type: ignore

        raw_user_info_from_provider.from_user_info_api = {
            **raw_user_info_from_provider.from_user_info_api,
            **email_info,
        }

        return UserInfo(
            third_party_user_id=raw_user_info_from_provider.from_user_info_api.get("id"),  # type: ignore
            email=UserInfoEmail(
                email=raw_user_info_from_provider.from_user_info_api.get("email"),  # type: ignore
                is_verified=False,
            ),
        )


def Linkedin(input: ProviderInput) -> Provider:  # pylint: disable=redefined-builtin
    if input.config.name is None:
        input.config.name = "Linkedin"

    if input.config.authorization_endpoint is None:
        input.config.authorization_endpoint = (
            "https://www.linkedin.com/oauth/v2/authorization"
        )

    if input.config.token_endpoint is None:
        input.config.token_endpoint = "https://www.linkedin.com/oauth/v2/accessToken"

    if input.config.user_info_map is None:
        input.config.user_info_map = UserInfoMap(UserFields(), UserFields())

    if input.config.user_info_map.from_user_info_api is None:
        input.config.user_info_map.from_user_info_api = UserFields()

    if input.config.user_info_map.from_user_info_api.user_id is None:
        input.config.user_info_map.from_user_info_api.user_id = "id"

    if input.config.user_info_map.from_user_info_api.email is None:
        input.config.user_info_map.from_user_info_api.email = "email"

    if input.config.user_info_map.from_user_info_api.email_verified is None:
        input.config.user_info_map.from_user_info_api.email = "verified"

    return NewProvider(input, LinkedinImpl)
