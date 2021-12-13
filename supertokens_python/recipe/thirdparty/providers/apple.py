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
from supertokens_python.recipe.thirdparty.api.implementation import get_actual_client_id_from_development_client_id
from supertokens_python.recipe.thirdparty.constants import APPLE_REDIRECT_HANDLER
from supertokens_python.supertokens import Supertokens
from jwt import encode, decode
from time import time
from re import sub
from httpx import AsyncClient
from jwt.algorithms import RSAAlgorithm, RSAPublicKey

if TYPE_CHECKING:
    from supertokens_python.framework.request import BaseRequest


class Apple(Provider):
    def __init__(self, client_id: str, client_key_id: str, client_private_key: str, client_team_id: str,
                 scope: List[str] = None,
                 authorisation_redirect: Dict[str, Union[str, Callable[[BaseRequest], str]]] = None,
                 is_default: bool = False):
        super().__init__('apple', client_id, is_default)
        self.APPLE_PUBLIC_KEY_URL = "https://appleid.apple.com/auth/keys"
        self.APPLE_PUBLIC_KEYS = []
        self.APPLE_KEY_CACHE_EXP = 60 * 60 * 24
        self.APPLE_LAST_KEY_FETCH = 0
        default_scopes = ['email']

        if scope is None:
            scope = default_scopes
        self.client_key_id = client_key_id
        self.client_private_key = client_private_key
        self.client_team_id = client_team_id
        self.scopes = list(set(scope))
        self.access_token_api_url = 'https://appleid.apple.com/auth/token'
        self.authorisation_redirect_url = 'https://appleid.apple.com/auth/authorize'
        self.authorisation_redirect_params = {}
        if authorisation_redirect is not None:
            self.authorisation_redirect_params = authorisation_redirect

    def __get_client_secret(self) -> str:
        payload = {
            'iss': self.client_team_id,
            'iat': time(),
            'exp': time() + (86400 * 180),  # 6 months
            'aud': 'https://appleid.apple.com',
            'sub': get_actual_client_id_from_development_client_id(self.client_id)
        }
        headers = {
            'kid': self.client_key_id
        }
        return encode(payload, sub(
            r'\\n', '\n', self.client_private_key), algorithm='ES256', headers=headers)

    async def get_profile_info(self, auth_code_response: any) -> UserInfo:
        # - Verify the JWS E256 signature using the server’s public key
        # - Verify the nonce for the authentication
        # - Verify that the iss field contains https://appleid.apple.com
        # - Verify that the aud field is the developer’s client_id
        # - Verify that the time is earlier than the exp value of the token
        await self._verify_apple_id_token(auth_code_response['id_token'])
        payload = decode(
            jwt=auth_code_response['id_token'], options={
                'verify_signature': False})
        if payload is None:
            raise Exception(
                'no user info found from user\'s id token received from apple')
        if 'email' not in payload or payload['email'] is None:
            raise Exception(
                'no user info found from user\'s id token received from apple')

        user_id = payload['sub']
        email = payload['email']
        is_email_verified = payload['email_verified'] if 'email_verified' in payload else False
        return UserInfo(user_id, UserInfoEmail(email, is_email_verified))

    def get_authorisation_redirect_api_info(self) -> AuthorisationRedirectAPI:
        params = {
            'scope': ' '.join(self.scopes),
            'response_type': 'code',
            'response_mode': 'form_post',
            'client_id': self.client_id,
            **self.authorisation_redirect_params
        }
        return AuthorisationRedirectAPI(
            self.authorisation_redirect_url, params)

    def get_access_token_api_info(
            self, redirect_uri: str, auth_code_from_request: str) -> AccessTokenAPI:
        params = {
            'client_id': self.client_id,
            'client_secret': self.__get_client_secret(),
            'grant_type': 'authorization_code',
            'code': auth_code_from_request,
            'redirect_uri': redirect_uri
        }
        return AccessTokenAPI(self.access_token_api_url, params)

    def get_redirect_uri(self) -> Union[None, str]:
        app_info = Supertokens.get_instance().app_info
        self.redirect_uri = app_info.api_domain.get_as_string_dangerous()
        self.redirect_uri += app_info.api_base_path.get_as_string_dangerous()
        self.redirect_uri += APPLE_REDIRECT_HANDLER
        return self.redirect_uri

    async def _fetch_apple_public_keys(self) -> List[RSAPublicKey]:
        # Check to see if the public key is unset or is stale before returning
        if (self.APPLE_LAST_KEY_FETCH + self.APPLE_KEY_CACHE_EXP) < int(time()) or len(self.APPLE_PUBLIC_KEYS) == 0:
            async with AsyncClient() as client:
                response = await client.get(self.APPLE_PUBLIC_KEY_URL)
                key_payload = response.json()
                for key in key_payload["keys"]:
                    self.APPLE_PUBLIC_KEYS.append(RSAAlgorithm.from_jwk(key))
                self.APPLE_LAST_KEY_FETCH = int(time())

        return self.APPLE_PUBLIC_KEYS

    async def _verify_apple_id_token(self, token):
        public_keys = await self._fetch_apple_public_keys()
        err = "Id token verification failed"
        for key in public_keys:
            try:
                decode(jwt=token, key=key,
                       audience=[get_actual_client_id_from_development_client_id(self.client_id)], algorithms=["RS256"])
                return
            except Exception as e:
                err = e
        raise err
