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

from typing import TYPE_CHECKING
from urllib.parse import urlencode

from httpx import AsyncClient
from supertokens_python.recipe.thirdparty.constants import DEV_OAUTH_AUTHORIZATION_URL, DEV_OAUTH_REDIRECT_URL
from supertokens_python.recipe.thirdparty.utils import is_using_oauth_development_keys
from supertokens_python.exceptions import raise_general_exception
from supertokens_python.recipe.session.asyncio import create_new_session
from supertokens_python.recipe.thirdparty.interfaces import APIInterface, SignInUpPostOkResponse, \
    AuthorisationUrlGetOkResponse, SignInUpPostNoEmailGivenByProviderResponse

if TYPE_CHECKING:
    from supertokens_python.recipe.thirdparty.interfaces import APIOptions, SignInUpPostResponse, \
        AuthorisationUrlGetResponse
    from supertokens_python.recipe.thirdparty.provider import Provider


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
        if is_using_oauth_development_keys(provider.client_id):
            params['actual_redirect_uri'] = authorisation_url_info.url
            auth_url = DEV_OAUTH_AUTHORIZATION_URL

        query_string = urlencode(params)

        url = auth_url + '?' + query_string
        return AuthorisationUrlGetOkResponse(url)

    async def sign_in_up_post(self, provider: Provider, code: str, redirect_uri: str,
                              api_options: APIOptions) -> SignInUpPostResponse:
        if is_using_oauth_development_keys(provider.client_id):
            redirect_uri = DEV_OAUTH_REDIRECT_URL
        try:
            access_token_api_info = provider.get_access_token_api_info(
                redirect_uri, code)
            headers = {
                'Accept': 'application/json',
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            async with AsyncClient() as client:
                access_token_response = await client.post(access_token_api_info.url, data=access_token_api_info.params,
                                                          headers=headers)
                access_token_response = access_token_response.json()
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
