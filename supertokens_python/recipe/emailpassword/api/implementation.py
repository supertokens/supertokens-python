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

from typing import TYPE_CHECKING, Any, Dict, List

from supertokens_python.recipe.emailpassword.constants import (
    FORM_FIELD_EMAIL_ID, FORM_FIELD_PASSWORD_ID)
from supertokens_python.recipe.emailpassword.interfaces import (
    APIInterface, EmailExistsGetOkResponse,
    GeneratePasswordResetTokenPostOkResponse,
    PasswordResetPostInvalidTokenResponse, PasswordResetPostOkResponse,
    SignInPostOkResponse, SignInPostWrongCredentialsErrorResponse,
    SignUpPostEmailAlreadyExistsErrorResponse, SignUpPostOkResponse)
from supertokens_python.recipe.emailpassword.types import FormField
from supertokens_python.recipe.session.asyncio import create_new_session
from supertokens_python.utils import find_first_occurrence_in_list

if TYPE_CHECKING:
    from supertokens_python.recipe.emailpassword.interfaces import (
        APIOptions, EmailExistsGetResponse,
        GeneratePasswordResetTokenPostResponse, PasswordResetPostResponse,
        SignInPostResponse, SignUpPostResponse)


class APIImplementation(APIInterface):
    async def email_exists_get(self, email: str, api_options: APIOptions, user_context: Dict[str, Any]) -> EmailExistsGetResponse:
        user = await api_options.recipe_implementation.get_user_by_email(email, user_context)
        return EmailExistsGetOkResponse(user is not None)

    async def generate_password_reset_token_post(self, form_fields: List[FormField],
                                                 api_options: APIOptions, user_context: Dict[str, Any]) -> GeneratePasswordResetTokenPostResponse:
        emailFormField = find_first_occurrence_in_list(
            lambda x: x.id == FORM_FIELD_EMAIL_ID, form_fields)
        if emailFormField is None:
            raise Exception("Should never come here")
        email = emailFormField.value

        user = await api_options.recipe_implementation.get_user_by_email(email, user_context)

        if user is None:
            return GeneratePasswordResetTokenPostOkResponse()

        token_result = await api_options.recipe_implementation.create_reset_password_token(user.user_id, user_context)

        if token_result.is_unknown_user_id_error or token_result.token is None:
            return GeneratePasswordResetTokenPostOkResponse()

        token = token_result.token
        password_reset_link = await api_options.config.reset_password_using_token_feature.get_reset_password_url(
            user, user_context) + '?token=' + token + '&rid=' + api_options.recipe_id

        try:
            await api_options.config.reset_password_using_token_feature.create_and_send_custom_email(user, password_reset_link, user_context)
        except Exception:
            pass

        return GeneratePasswordResetTokenPostOkResponse()

    async def password_reset_post(self, form_fields: List[FormField], token: str,
                                  api_options: APIOptions, user_context: Dict[str, Any]) -> PasswordResetPostResponse:
        new_password_for_field = find_first_occurrence_in_list(
            lambda x: x.id == FORM_FIELD_PASSWORD_ID, form_fields)
        if new_password_for_field is None:
            raise Exception("Should never come here")
        new_password = new_password_for_field.value

        result = await api_options.recipe_implementation.reset_password_using_token(token, new_password, user_context)
        if result.is_ok:
            return PasswordResetPostOkResponse(result.user_id)
        return PasswordResetPostInvalidTokenResponse()

    async def sign_in_post(self, form_fields: List[FormField], api_options: APIOptions, user_context: Dict[str, Any]) -> SignInPostResponse:
        password_form_field = find_first_occurrence_in_list(
            lambda x: x.id == FORM_FIELD_PASSWORD_ID, form_fields)
        if password_form_field is None:
            raise Exception("Should never come here")
        password = password_form_field.value

        email_form_field = find_first_occurrence_in_list(
            lambda x: x.id == FORM_FIELD_EMAIL_ID, form_fields)
        if email_form_field is None:
            raise Exception("Should never come here")
        email = email_form_field.value

        result = await api_options.recipe_implementation.sign_in(email, password, user_context)

        if result.is_wrong_credentials_error or result.user is None:
            return SignInPostWrongCredentialsErrorResponse()

        user = result.user
        session = await create_new_session(api_options.request, user.user_id, user_context=user_context)
        return SignInPostOkResponse(user, session)

    async def sign_up_post(self, form_fields: List[FormField], api_options: APIOptions, user_context: Dict[str, Any]) -> SignUpPostResponse:
        password_form_field = find_first_occurrence_in_list(
            lambda x: x.id == FORM_FIELD_PASSWORD_ID, form_fields)
        if password_form_field is None:
            raise Exception("Should never come here")
        password = password_form_field.value

        email_form_field = find_first_occurrence_in_list(
            lambda x: x.id == FORM_FIELD_EMAIL_ID, form_fields)
        if email_form_field is None:
            raise Exception("Should never come here")
        email = email_form_field.value

        result = await api_options.recipe_implementation.sign_up(email, password, user_context)

        if result.is_email_already_exists_error or result.user is None:
            return SignUpPostEmailAlreadyExistsErrorResponse()

        user = result.user
        session = await create_new_session(api_options.request, user.user_id, user_context=user_context)
        return SignUpPostOkResponse(user, session)
