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

import base64
from typing import Any, Dict, List, Optional

from supertokens_python.recipe.thirdparty.providers.utils import (
    do_get_request,
    do_post_request,
)
from supertokens_python.recipe.thirdparty.types import UserInfo, UserInfoEmail

from ..provider import Provider, ProviderConfigForClient, ProviderInput
from ..types import RawUserInfoFromProvider
from .custom import GenericProvider, NewProvider


class GithubImpl(GenericProvider):
    async def get_config_for_client_type(
        self, client_type: Optional[str], user_context: Dict[str, Any]
    ) -> ProviderConfigForClient:
        config = await super().get_config_for_client_type(client_type, user_context)

        if config.scope is None:
            config.scope = ["read:user", "user:email"]

        return config

    async def get_user_info(
        self, oauth_tokens: Dict[str, Any], user_context: Dict[str, Any]
    ) -> UserInfo:
        headers = {
            "Authorization": f"Bearer {oauth_tokens.get('access_token')}",
            "Accept": "application/vnd.github.v3+json",
        }

        # https://docs.github.com/en/rest/users/emails?apiVersion=2022-11-28
        user_info = await do_get_request("https://api.github.com/user", headers=headers)
        user_email_info: List[Any] = await do_get_request(
            "https://api.github.com/user/emails", headers=headers
        )  # type: ignore

        raw_user_info_from_provider = RawUserInfoFromProvider({}, {})
        raw_user_info_from_provider.from_user_info_api = user_info
        raw_user_info_from_provider.from_user_info_api["emails"] = user_email_info

        # Get the primary email from the Email response
        # Create an object if primary email found
        primary_email_info: UserInfoEmail | None = None
        for email_detail in user_email_info:
            if email_detail["primary"]:
                primary_email_info = UserInfoEmail(
                    email=email_detail["email"],
                    is_verified=email_detail["verified"],
                )
                break

        result = UserInfo(
            third_party_user_id=str(user_info["id"]),
            email=primary_email_info,
            raw_user_info_from_provider=raw_user_info_from_provider,
        )

        return result


def Github(input: ProviderInput) -> Provider:  # pylint: disable=redefined-builtin
    if not input.config.name:
        input.config.name = "Github"

    if not input.config.authorization_endpoint:
        input.config.authorization_endpoint = "https://github.com/login/oauth/authorize"

    if not input.config.token_endpoint:
        input.config.token_endpoint = "https://github.com/login/oauth/access_token"

    if input.config.validate_access_token is None:
        input.config.validate_access_token = validate_access_token

    return NewProvider(input, GithubImpl)


async def validate_access_token(
    access_token: str, config: ProviderConfigForClient, _: Dict[str, Any]
):
    client_secret = "" if config.client_secret is None else config.client_secret
    basic_auth_token = base64.b64encode(
        f"{config.client_id}:{client_secret}".encode()
    ).decode()

    url = f"https://api.github.com/applications/{config.client_id}/token"
    headers = {
        "Authorization": f"Basic {basic_auth_token}",
        "Content-Type": "application/json",
    }

    status, body = await do_post_request(url, {"access_token": access_token}, headers)
    if status != 200:
        raise ValueError("Invalid access token")

    if "app" not in body or body["app"].get("client_id") != config.client_id:
        raise ValueError("Access token does not belong to your application")
