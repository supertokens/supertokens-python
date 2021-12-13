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

from supertokens_python.recipe.thirdparty.provider import Provider
from typing import List, Union, Dict, Callable, TYPE_CHECKING
from supertokens_python.recipe.thirdparty.types import UserInfo, AccessTokenAPI, AuthorisationRedirectAPI, UserInfoEmail
from httpx import AsyncClient

if TYPE_CHECKING:
    from supertokens_python.framework.request import BaseRequest


class Discord(Provider):
    def __init__(self, client_id: str, client_secret: str, scope: List[str] = None,
                 authorisation_redirect: Dict[str, Union[str, Callable[[BaseRequest], str]]] = None,
                 is_default: bool = False):
        super().__init__('discord', client_id, is_default)
        default_scopes = ["email", "identify"]
        if scope is None:
            scope = default_scopes
        self.client_secret = client_secret
        self.base_url = 'https://discord.com'
        self.scopes = list(set(scope))
        self.access_token_api_url = self.base_url + '/api/oauth2/token'
        self.authorisation_redirect_url = self.base_url + '/api/oauth2/authorize'
        self.authorisation_redirect_params = {}
        if authorisation_redirect is not None:
            self.authorisation_redirect_params = authorisation_redirect

    async def get_profile_info(self, auth_code_response: any) -> UserInfo:
        access_token: str = auth_code_response['access_token']
        headers = {
            'Authorization': 'Bearer ' + access_token
        }
        async with AsyncClient() as client:
            response = await client.get(url=self.base_url + '/api/users/@me', headers=headers)
            user_info = response.json()
            user_id = user_info['id']
            if 'email' not in user_info or user_info['email'] is None:
                return UserInfo(user_id)
            is_email_verified = user_info['verified'] if 'verified' in user_info else False
            return UserInfo(user_id, UserInfoEmail(
                user_info['email'], is_email_verified))

    def get_authorisation_redirect_api_info(self) -> AuthorisationRedirectAPI:
        params = {
            'scope': ' '.join(self.scopes),
            'client_id': self.client_id,
            'response_type': 'code',
            **self.authorisation_redirect_params
        }
        return AuthorisationRedirectAPI(
            self.authorisation_redirect_url, params)

    def get_access_token_api_info(
            self, redirect_uri: str, auth_code_from_request: str) -> AccessTokenAPI:
        params = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'grant_type': 'authorization_code',
            'code': auth_code_from_request,
            'redirect_uri': redirect_uri
        }
        return AccessTokenAPI(self.access_token_api_url, params)
