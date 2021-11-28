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

from typing import TYPE_CHECKING, List

from supertokens_python.recipe.emailpassword.constants import FORM_FIELD_EMAIL_ID, FORM_FIELD_PASSWORD_ID
from supertokens_python.recipe.emailpassword.interfaces import (
    APIInterface, EmailExistsGetOkResponse, GeneratePasswordResetTokenPostOkResponse,
    PasswordResetPostOkResponse, PasswordResetPostInvalidTokenResponse, SignInPostOkResponse,
    SignInPostWrongCredentialsErrorResponse, SignUpPostOkResponse,
    SignUpPostEmailAlreadyExistsErrorResponse
)
from supertokens_python.recipe.emailpassword.types import FormField
from supertokens_python.recipe.session.asyncio import create_new_session
from supertokens_python.utils import find_first_occurrence_in_list

if TYPE_CHECKING:
    from supertokens_python.recipe.emailpassword.interfaces import (
        APIOptions, SignUpPostResponse, SignInPostResponse,
        PasswordResetPostResponse, GeneratePasswordResetTokenPostResponse, EmailExistsGetResponse
    )


class APIImplementation(APIInterface):
    def __init__(self):
        super().__init__()

    async def email_exists_get(self, email: str, api_options: APIOptions) -> EmailExistsGetResponse:
        user = await api_options.recipe_implementation.get_user_by_email(email)
        return EmailExistsGetOkResponse(user is not None)

    async def generate_password_reset_token_post(self, form_fields: List[FormField],
                                                 api_options: APIOptions) -> GeneratePasswordResetTokenPostResponse:
        email = find_first_occurrence_in_list(
            lambda x: x.id == FORM_FIELD_EMAIL_ID, form_fields).value

        user = await api_options.recipe_implementation.get_user_by_email(email)

        if user is None:
            return GeneratePasswordResetTokenPostOkResponse()

        token_result = await api_options.recipe_implementation.create_reset_password_token(user.user_id)

        if token_result.is_unknown_user_id_error or token_result.token is None:
            return GeneratePasswordResetTokenPostOkResponse()

        token = token_result.token
        password_reset_link = await api_options.config.reset_password_using_token_feature.get_reset_password_url(
            user) + '?token=' + token + '&rid=' + api_options.recipe_id

        try:
            await api_options.config.reset_password_using_token_feature.create_and_send_custom_email(
                user, password_reset_link)
        except Exception:
            pass

        return GeneratePasswordResetTokenPostOkResponse()

    async def password_reset_post(self, form_fields: List[FormField], token: str,
                                  api_options: APIOptions) -> PasswordResetPostResponse:
        new_password = find_first_occurrence_in_list(
            lambda x: x.id == FORM_FIELD_PASSWORD_ID, form_fields).value
        result = await api_options.recipe_implementation.reset_password_using_token(token, new_password)
        if result.is_ok:
            return PasswordResetPostOkResponse()
        return PasswordResetPostInvalidTokenResponse()

    async def sign_in_post(self, form_fields: List[FormField], api_options: APIOptions) -> SignInPostResponse:
        password = find_first_occurrence_in_list(
            lambda x: x.id == FORM_FIELD_PASSWORD_ID, form_fields).value
        email = find_first_occurrence_in_list(
            lambda x: x.id == FORM_FIELD_EMAIL_ID, form_fields).value

        result = await api_options.recipe_implementation.sign_in(email, password)

        if result.is_wrong_credentials_error or result.user is None:
            return SignInPostWrongCredentialsErrorResponse()

        user = result.user
        await create_new_session(api_options.request, user.user_id)
        return SignInPostOkResponse(user)

    async def sign_up_post(self, form_fields: List[FormField], api_options: APIOptions) -> SignUpPostResponse:
        password = find_first_occurrence_in_list(
            lambda x: x.id == FORM_FIELD_PASSWORD_ID, form_fields).value
        email = find_first_occurrence_in_list(
            lambda x: x.id == FORM_FIELD_EMAIL_ID, form_fields).value

        result = await api_options.recipe_implementation.sign_up(email, password)

        if result.is_email_already_exists_error or result.user is None:
            return SignUpPostEmailAlreadyExistsErrorResponse()

        user = result.user
        await create_new_session(api_options.request, user.user_id)
        return SignUpPostOkResponse(user)
