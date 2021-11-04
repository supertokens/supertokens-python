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

from typing import TYPE_CHECKING, Union
from urllib.parse import urlencode

from httpx import AsyncClient
from supertokens_python.exceptions import raise_general_exception
from supertokens_python.recipe.session.asyncio import create_new_session
from supertokens_python.recipe.thirdparty.interfaces import APIInterface, SignInUpPostOkResponse, \
    AuthorisationUrlGetOkResponse, SignInUpPostNoEmailGivenByProviderResponse

if TYPE_CHECKING:
    from supertokens_python.recipe.thirdparty.interfaces import APIOptions, SignInUpPostResponse, \
        AuthorisationUrlGetResponse
    from supertokens_python.recipe.thirdparty.provider import Provider


DEV_OAUTH_CLIENT_IDS = [
    '1060725074195-kmeum4crr01uirfl2op9kd5acmi9jutn.apps.googleusercontent.com',  # google client id
    '467101b197249757c71f'  # github client id
]
DEV_KEY_IDENTIFIER = "4398792-"
DEV_OAUTH_AUTHORIZATION_URL = 'https://supertokens.io/dev/oauth/redirect-to-provider'
DEV_OAUTH_REDIRECT_URL = 'https://supertokens.io/dev/oauth/redirect-to-app'


def is_using_oauth_development_client_id(client_id: str):
    return client_id.startswith(DEV_KEY_IDENTIFIER) or client_id in DEV_OAUTH_CLIENT_IDS


def get_actual_client_id_from_development_client_id(client_id: str):
    if client_id.startswith(DEV_KEY_IDENTIFIER):
        return client_id.split(DEV_KEY_IDENTIFIER, 1)[1]
    return client_id


class APIImplementation(APIInterface):
    def __init__(self):
        super().__init__()

    async def authorisation_url_get(self, provider: Provider, api_options: APIOptions) -> AuthorisationUrlGetResponse:
        authorisation_url_info = provider.get_authorisation_redirect_api_info()

        params = {}
        for key, value in authorisation_url_info.params.items():
            params[key] = value if not callable(
                value) else value(api_options.request)

        auth_url = authorisation_url_info.url
        if is_using_oauth_development_client_id(provider.client_id):
            params['actual_redirect_uri'] = authorisation_url_info.url

            for k, v in params:
                if params[k] == provider.client_id:
                    params[k] = get_actual_client_id_from_development_client_id(provider.client_id)
            auth_url = DEV_OAUTH_AUTHORIZATION_URL

        query_string = urlencode(params)

        url = auth_url + '?' + query_string
        return AuthorisationUrlGetOkResponse(url)

    async def sign_in_up_post(self, provider: Provider, code: str, redirect_uri: str,
                              auth_code_response: Union[str, None], api_options: APIOptions) -> SignInUpPostResponse:
        if is_using_oauth_development_client_id(provider.client_id):
            redirect_uri = DEV_OAUTH_REDIRECT_URL
        try:
            if auth_code_response is None:
                access_token_api_info = provider.get_access_token_api_info(
                    redirect_uri, code)
                if is_using_oauth_development_client_id(provider.client_id):
                    for k, v in access_token_api_info.params:
                        if access_token_api_info.params[k] == provider.client_id:
                            access_token_api_info.params[k] = get_actual_client_id_from_development_client_id(
                                provider.client_id)
                headers = {
                    'Accept': 'application/json',
                    'Content-Type': 'application/x-www-form-urlencoded'
                }
                async with AsyncClient() as client:
                    access_token_response = await client.post(access_token_api_info.url, data=access_token_api_info.params,
                                                              headers=headers)
                    access_token_response = access_token_response.json()
            else:
                access_token_response = auth_code_response
            user_info = await provider.get_profile_info(access_token_response)
        except Exception as e:
            raise_general_exception(e)

        email = user_info.email.id if user_info.email is not None else None
        email_verified = user_info.email.is_verified if user_info.email is not None else None
        if email is None or email_verified is None:
            return SignInUpPostNoEmailGivenByProviderResponse()

        signinup_response = await api_options.recipe_implementation.sign_in_up(provider.id, user_info.user_id, email,
                                                                               email_verified)
        user = signinup_response.user
        await create_new_session(api_options.request, user.user_id)

        return SignInUpPostOkResponse(
            user, signinup_response.created_new_user, access_token_response)
