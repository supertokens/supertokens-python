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


from supertokens_python.utils import get_filtered_list


class Github(Provider):
    def __init__(self, client_id: str, client_secret: str, scope: List[str] = None,
                 authorisation_redirect: Dict[str, Union[str, Callable[[BaseRequest], str]]] = None,
                 is_default: bool = False):
        super().__init__('github', client_id, is_default)
        default_scopes = ["read:user", "user:email"]
        if scope is None:
            scope = default_scopes
        self.client_secret = client_secret
        self.scopes = list(set(scope))
        self.access_token_api_url = 'https://github.com/login/oauth/access_token'
        self.authorisation_redirect_url = 'https://github.com/login/oauth/authorize'
        self.authorisation_redirect_params = {}
        if authorisation_redirect is not None:
            self.authorisation_redirect_params = authorisation_redirect

    async def get_profile_info(self, auth_code_response: any) -> UserInfo:
        access_token: str = auth_code_response['access_token']
        params = {
            'alt': 'json'
        }
        headers = {
            'Authorization': 'Bearer ' + access_token,
            'Accept': 'application/vnd.github.v3+json'
        }
        async with AsyncClient() as client:
            response_user = await client.get(url='https://api.github.com/user', params=params, headers=headers)
            response_email = await client.get(url='https://api.github.com/user/emails', params=params, headers=headers)
            user_info = response_user.json()
            emails_info = response_email.json()
            user_id = str(user_info['id'])
            email_info = get_filtered_list(
                lambda x: 'primary' in x and x['primary'], emails_info)

            if len(email_info) == 0:
                return UserInfo(user_id)
            is_email_verified = email_info[0]['verified'] if 'verified' in email_info[0] else False
            email = email_info[0]['email'] if 'email' in email_info[0] else user_info['email']
            return UserInfo(user_id, UserInfoEmail(email, is_email_verified))

    def get_authorisation_redirect_api_info(self) -> AuthorisationRedirectAPI:
        params = {
            'scope': ' '.join(self.scopes),
            'client_id': self.client_id,
            **self.authorisation_redirect_params
        }
        return AuthorisationRedirectAPI(
            self.authorisation_redirect_url, params)

    def get_access_token_api_info(
            self, redirect_uri: str, auth_code_from_request: str) -> AccessTokenAPI:
        params = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'code': auth_code_from_request,
            'redirect_uri': redirect_uri
        }
        return AccessTokenAPI(self.access_token_api_url, params)
