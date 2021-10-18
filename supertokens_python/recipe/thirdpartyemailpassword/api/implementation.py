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

from typing import List

from supertokens_python.recipe.emailpassword.api.implementation import APIImplementation as EmailPasswordImplementation
from supertokens_python.recipe.emailpassword.interfaces import APIOptions as EmailPasswordAPIOptions, \
    PasswordResetPostResponse, \
    GeneratePasswordResetTokenPostResponse, EmailExistsGetResponse
from supertokens_python.recipe.emailpassword.types import FormField
from supertokens_python.recipe.thirdparty.api.implementation import APIImplementation as ThirdPartyImplementation
from supertokens_python.recipe.thirdparty.interfaces import APIOptions, \
    AuthorisationUrlGetResponse
from supertokens_python.recipe.thirdparty.provider import Provider
from supertokens_python.recipe.thirdpartyemailpassword.interfaces import SignInUpAPIInput, APIInterface


class APIImplementation(APIInterface):
    def __init__(self):
        super().__init__()
        self.email_password_implementation = EmailPasswordImplementation()
        self.third_party_implementation = ThirdPartyImplementation()

    async def email_exists_get(self, email: str, options: EmailPasswordAPIOptions) -> EmailExistsGetResponse:
        return await self.email_password_implementation.email_exists_get(email, options)

    async def generate_password_reset_token_post(self, form_fields: List[FormField],
                                                 options: EmailPasswordAPIOptions) -> GeneratePasswordResetTokenPostResponse:
        return await self.email_password_implementation.generate_password_reset_token_post(form_fields, options)

    async def password_reset_post(self, form_fields: List[FormField], token: str,
                                  options: EmailPasswordAPIOptions) -> PasswordResetPostResponse:
        return await self.email_password_implementation.password_reset_post(form_fields, token, options)

    async def sign_in_up_post(self, sign_in_up_input: SignInUpAPIInput):
        if sign_in_up_input.type == 'emailpassword':
            if sign_in_up_input.is_sign_in:
                return await self.email_password_implementation.sign_in_post(sign_in_up_input.form_fields,
                                                                             sign_in_up_input.options)
            else:
                return await self.email_password_implementation.sign_up_post(sign_in_up_input.form_fields,
                                                                             sign_in_up_input.options)
        else:
            return await self.third_party_implementation.sign_in_up_post(sign_in_up_input.provider,
                                                                         sign_in_up_input.code,
                                                                         sign_in_up_input.redirect_uri,
                                                                         sign_in_up_input.options)

    async def authorisation_url_get(self, provider: Provider, api_options: APIOptions) -> AuthorisationUrlGetResponse:
        return await self.third_party_implementation.authorisation_url_get(provider, api_options)
