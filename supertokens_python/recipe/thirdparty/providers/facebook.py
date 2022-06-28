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

from typing import TYPE_CHECKING, Any, Callable, Dict, List, Union

from httpx import AsyncClient
from supertokens_python.recipe.thirdparty.provider import Provider
from supertokens_python.recipe.thirdparty.types import (
    AccessTokenAPI,
    AuthorisationRedirectAPI,
    UserInfo,
    UserInfoEmail,
)

if TYPE_CHECKING:
    from supertokens_python.framework.request import BaseRequest


class Facebook(Provider):
    def __init__(
        self,
        client_id: str,
        client_secret: str,
        scope: Union[None, List[str]] = None,
        is_default: bool = False,
    ):
        super().__init__("facebook", is_default)
        default_scopes = ["email"]

        if scope is None:
            scope = default_scopes
        self.client_id = client_id
        self.client_secret = client_secret
        self.scopes = list(set(scope))
        self.access_token_api_url = "https://graph.facebook.com/v9.0/oauth/access_token"
        self.authorisation_redirect_url = "https://www.facebook.com/v9.0/dialog/oauth"

    async def get_profile_info(
        self, auth_code_response: Dict[str, Any], user_context: Dict[str, Any]
    ) -> UserInfo:
        access_token: str = auth_code_response["access_token"]

        params = {"access_token": access_token, "fields": "id,email", "format": "json"}
        async with AsyncClient() as client:
            response = await client.get(
                url="https://graph.facebook.com/me", params=params
            )
            user_info = response.json()
            user_id = user_info["id"]
            if "email" not in user_info or user_info["email"] is None:
                return UserInfo(user_id)
            return UserInfo(user_id, UserInfoEmail(user_info["email"], True))

    def get_authorisation_redirect_api_info(
        self, user_context: Dict[str, Any]
    ) -> AuthorisationRedirectAPI:
        params: Dict[str, Union[Callable[[BaseRequest], str], str]] = {
            "scope": " ".join(self.scopes),
            "response_type": "code",
            "client_id": self.client_id,
        }
        return AuthorisationRedirectAPI(self.authorisation_redirect_url, params)

    def get_access_token_api_info(
        self,
        redirect_uri: str,
        auth_code_from_request: str,
        user_context: Dict[str, Any],
    ) -> AccessTokenAPI:
        params = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": auth_code_from_request,
            "redirect_uri": redirect_uri,
        }
        return AccessTokenAPI(self.access_token_api_url, params)

    def get_redirect_uri(self, user_context: Dict[str, Any]) -> Union[None, str]:
        return None

    def get_client_id(self, user_context: Dict[str, Any]) -> str:
        return self.client_id
