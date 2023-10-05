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

from base64 import b64encode
from typing import Any, Dict, Optional
from supertokens_python.recipe.thirdparty.provider import RedirectUriInfo
from supertokens_python.recipe.thirdparty.providers.utils import (
    do_post_request,
    DEV_OAUTH_REDIRECT_URL,
    get_actual_client_id_from_development_client_id,
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
    is_using_development_client_id,
)


class TwitterImpl(GenericProvider):
    async def get_config_for_client_type(
        self, client_type: Optional[str], user_context: Dict[str, Any]
    ) -> ProviderConfigForClient:
        config = await super().get_config_for_client_type(client_type, user_context)

        if config.scope is None:
            config.scope = ["users.read", "tweet.read"]

        if config.force_pkce is None:
            config.force_pkce = True

        return config

    async def exchange_auth_code_for_oauth_tokens(
        self, redirect_uri_info: RedirectUriInfo, user_context: Dict[str, Any]
    ) -> Dict[str, Any]:

        client_id = self.config.client_id
        redirect_uri = redirect_uri_info.redirect_uri_on_provider_dashboard

        # We need to do this because we don't call the original implementation
        # Transformation needed for dev keys BEGIN
        if is_using_development_client_id(self.config.client_id):
            client_id = get_actual_client_id_from_development_client_id(
                self.config.client_id
            )
            redirect_uri = DEV_OAUTH_REDIRECT_URL
        # Transformation needed for dev keys END

        credentials = client_id + ":" + (self.config.client_secret or "")
        auth_token = b64encode(credentials.encode()).decode()

        twitter_oauth_tokens_params: Dict[str, Any] = {
            "grant_type": "authorization_code",
            "client_id": client_id,
            "code_verifier": redirect_uri_info.pkce_code_verifier,
            "redirect_uri": redirect_uri,
            "code": redirect_uri_info.redirect_uri_query_params["code"],
        }

        twitter_oauth_tokens_params = {
            **twitter_oauth_tokens_params,
            **(self.config.token_endpoint_body_params or {}),
        }

        assert self.config.token_endpoint is not None

        _, body = await do_post_request(
            self.config.token_endpoint,
            body_params=twitter_oauth_tokens_params,
            headers={"Authorization": f"Basic {auth_token}"},
        )
        return body


def Twitter(input: ProviderInput) -> Provider:  # pylint: disable=redefined-builtin
    if input.config.name is None:
        input.config.name = "Twitter"

    if input.config.authorization_endpoint is None:
        input.config.authorization_endpoint = "https://twitter.com/i/oauth2/authorize"

    if input.config.token_endpoint is None:
        input.config.token_endpoint = "https://api.twitter.com/2/oauth2/token"

    if input.config.user_info_endpoint is None:
        input.config.user_info_endpoint = "https://api.twitter.com/2/users/me"

    if input.config.require_email is None:
        input.config.require_email = False

    if input.config.user_info_map is None:
        input.config.user_info_map = UserInfoMap(UserFields(), UserFields())

    if input.config.user_info_map.from_user_info_api is None:
        input.config.user_info_map.from_user_info_api = UserFields()

    if input.config.user_info_map.from_user_info_api.user_id is None:
        input.config.user_info_map.from_user_info_api.user_id = "data.id"

    return NewProvider(input, TwitterImpl)
