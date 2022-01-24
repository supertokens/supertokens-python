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

from typing import List, Union

from supertokens_python.recipe.emailpassword.api.implementation import APIImplementation as EmailPasswordImplementation
from supertokens_python.recipe.emailpassword.interfaces import APIOptions as EmailPasswordAPIOptions, \
    PasswordResetPostResponse, \
    GeneratePasswordResetTokenPostResponse, EmailExistsGetResponse, APIOptions as EmailPasswordApiOptions, \
    SignUpPostResponse, SignInPostResponse
from supertokens_python.recipe.emailpassword.types import FormField
from supertokens_python.recipe.thirdparty.api.implementation import APIImplementation as ThirdPartyImplementation
from supertokens_python.recipe.thirdparty.interfaces import APIOptions, \
    AuthorisationUrlGetResponse, APIOptions as ThirdPartyApiOptions, SignInUpPostResponse
from supertokens_python.recipe.thirdparty.provider import Provider
from supertokens_python.recipe.thirdpartyemailpassword.interfaces import APIInterface
from .emailpassword_api_impementation import get_interface_impl as get_ep_interface_impl
from .thirdparty_api_implementation import get_interface_impl as get_tp_interface_impl


class APIImplementation(APIInterface):
    def __init__(self):
        super().__init__()
        emailpassword_implementation = EmailPasswordImplementation()
        self.ep_email_exists_get = emailpassword_implementation.email_exists_get
        self.ep_generate_password_reset_token_post = emailpassword_implementation.generate_password_reset_token_post
        self.ep_password_reset_post = emailpassword_implementation.password_reset_post
        self.ep_sign_in_post = emailpassword_implementation.sign_in_post
        self.ep_sign_up_post = emailpassword_implementation.sign_up_post
        emailpassword_implementation = get_ep_interface_impl(self)
        thirdparty_implementation = ThirdPartyImplementation()
        self.tp_authorisation_url_get = thirdparty_implementation.authorisation_url_get
        self.tp_sign_in_up_post = thirdparty_implementation.sign_in_up_post
        self.tp_apple_redirect_handler_post = thirdparty_implementation.apple_redirect_handler_post
        thirdparty_implementation = get_tp_interface_impl(self)

    async def email_exists_get(self, email: str, options: EmailPasswordAPIOptions, user_context: any) -> EmailExistsGetResponse:
        return await self.ep_email_exists_get(email, options, user_context)

    async def generate_password_reset_token_post(self, form_fields: List[FormField],
                                                 options: EmailPasswordAPIOptions, user_context: any) -> GeneratePasswordResetTokenPostResponse:
        return await self.ep_generate_password_reset_token_post(form_fields, options, user_context)

    async def password_reset_post(self, form_fields: List[FormField], token: str,
                                  options: EmailPasswordAPIOptions, user_context: any) -> PasswordResetPostResponse:
        return await self.ep_password_reset_post(form_fields, token, options, user_context)

    async def thirdparty_sign_in_up_post(self, provider: Provider, code: str, redirect_uri: str, client_id: Union[str, None],
                                         auth_code_response: Union[str, None], api_options: ThirdPartyApiOptions, user_context: any) -> SignInUpPostResponse:
        return await self.tp_sign_in_up_post(provider, code, redirect_uri, client_id, auth_code_response, api_options, user_context)

    async def emailpassword_sign_in_post(self, form_fields: List[FormField],
                                         api_options: EmailPasswordApiOptions, user_context: any) -> SignInPostResponse:
        return await self.ep_sign_in_post(form_fields, api_options, user_context)

    async def emailpassword_sign_up_post(self, form_fields: List[FormField],
                                         api_options: EmailPasswordApiOptions, user_context: any) -> SignUpPostResponse:
        return await self.ep_sign_up_post(form_fields, api_options, user_context)

    async def authorisation_url_get(self, provider: Provider, api_options: APIOptions, user_context: any) -> AuthorisationUrlGetResponse:
        return await self.tp_authorisation_url_get(provider, api_options, user_context)

    async def apple_redirect_handler_post(self, code: str, state: str, api_options: ThirdPartyApiOptions, user_context: any):
        return await self.tp_apple_redirect_handler_post(code, state, api_options, user_context)
