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

from typing import TYPE_CHECKING, Any, Dict, List, Union

from supertokens_python.logger import log_debug_message
from supertokens_python.recipe.emailpassword.constants import (
    FORM_FIELD_EMAIL_ID,
    FORM_FIELD_PASSWORD_ID,
)
from supertokens_python.recipe.emailpassword.interfaces import (
    APIInterface,
    CreateResetPasswordWrongUserIdError,
    EmailExistsGetOkResult,
    GeneratePasswordResetTokenPostOkResult,
    PasswordResetPostInvalidTokenResponse,
    PasswordResetPostOkResult,
    ResetPasswordUsingTokenInvalidTokenError,
    SignInPostOkResult,
    SignInPostWrongCredentialsError,
    SignInWrongCredentialsError,
    SignUpEmailAlreadyExistsError,
    SignUpPostEmailAlreadyExistsError,
    SignUpPostOkResult,
)
from supertokens_python.recipe.emailpassword.types import (
    FormField,
    PasswordResetEmailTemplateVars,
    PasswordResetEmailTemplateVarsUser,
)
from ..utils import get_password_reset_link
from supertokens_python.recipe.session.asyncio import create_new_session
from supertokens_python.utils import find_first_occurrence_in_list

if TYPE_CHECKING:
    from supertokens_python.recipe.emailpassword.interfaces import APIOptions

from supertokens_python.types import GeneralErrorResponse


class APIImplementation(APIInterface):
    async def email_exists_get(
        self,
        email: str,
        tenant_id: str,
        api_options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[EmailExistsGetOkResult, GeneralErrorResponse]:
        user = await api_options.recipe_implementation.get_user_by_email(
            email, tenant_id, user_context
        )
        return EmailExistsGetOkResult(user is not None)

    async def generate_password_reset_token_post(
        self,
        form_fields: List[FormField],
        tenant_id: str,
        api_options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[GeneratePasswordResetTokenPostOkResult, GeneralErrorResponse]:
        emailFormField = find_first_occurrence_in_list(
            lambda x: x.id == FORM_FIELD_EMAIL_ID, form_fields
        )
        if emailFormField is None:
            raise Exception("Should never come here")
        email = emailFormField.value

        user = await api_options.recipe_implementation.get_user_by_email(
            email, tenant_id, user_context
        )

        if user is None:
            return GeneratePasswordResetTokenPostOkResult()

        token_result = (
            await api_options.recipe_implementation.create_reset_password_token(
                user.user_id, tenant_id, user_context
            )
        )

        if isinstance(token_result, CreateResetPasswordWrongUserIdError):
            log_debug_message(
                "Password reset email not sent, unknown user id: %s", user.user_id
            )
            return GeneratePasswordResetTokenPostOkResult()

        password_reset_link = get_password_reset_link(
            api_options.app_info,
            token_result.token,
            api_options.recipe_id,
            tenant_id,
            api_options.request,
            user_context,
        )

        log_debug_message("Sending password reset email to %s", email)
        send_email_input = PasswordResetEmailTemplateVars(
            user=PasswordResetEmailTemplateVarsUser(user.user_id, user.email),
            password_reset_link=password_reset_link,
            tenant_id=tenant_id,
        )
        await api_options.email_delivery.ingredient_interface_impl.send_email(
            send_email_input, user_context
        )

        return GeneratePasswordResetTokenPostOkResult()

    async def password_reset_post(
        self,
        form_fields: List[FormField],
        token: str,
        tenant_id: str,
        api_options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[
        PasswordResetPostOkResult,
        PasswordResetPostInvalidTokenResponse,
        GeneralErrorResponse,
    ]:
        new_password_for_field = find_first_occurrence_in_list(
            lambda x: x.id == FORM_FIELD_PASSWORD_ID, form_fields
        )
        if new_password_for_field is None:
            raise Exception("Should never come here")
        new_password = new_password_for_field.value

        result = await api_options.recipe_implementation.reset_password_using_token(
            token, new_password, tenant_id, user_context
        )

        if isinstance(result, ResetPasswordUsingTokenInvalidTokenError):
            return PasswordResetPostInvalidTokenResponse()

        return PasswordResetPostOkResult(result.user_id)

    async def sign_in_post(
        self,
        form_fields: List[FormField],
        tenant_id: str,
        api_options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[
        SignInPostOkResult, SignInPostWrongCredentialsError, GeneralErrorResponse
    ]:
        password_form_field = find_first_occurrence_in_list(
            lambda x: x.id == FORM_FIELD_PASSWORD_ID, form_fields
        )
        if password_form_field is None:
            raise Exception("Should never come here")
        password = password_form_field.value

        email_form_field = find_first_occurrence_in_list(
            lambda x: x.id == FORM_FIELD_EMAIL_ID, form_fields
        )
        if email_form_field is None:
            raise Exception("Should never come here")
        email = email_form_field.value

        result = await api_options.recipe_implementation.sign_in(
            email, password, tenant_id, user_context
        )

        if isinstance(result, SignInWrongCredentialsError):
            return SignInPostWrongCredentialsError()

        user = result.user
        session = await create_new_session(
            tenant_id=tenant_id,
            request=api_options.request,
            user_id=user.user_id,
            access_token_payload={},
            session_data_in_database={},
            user_context=user_context,
        )
        return SignInPostOkResult(user, session)

    async def sign_up_post(
        self,
        form_fields: List[FormField],
        tenant_id: str,
        api_options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[
        SignUpPostOkResult, SignUpPostEmailAlreadyExistsError, GeneralErrorResponse
    ]:
        password_form_field = find_first_occurrence_in_list(
            lambda x: x.id == FORM_FIELD_PASSWORD_ID, form_fields
        )
        if password_form_field is None:
            raise Exception("Should never come here")
        password = password_form_field.value

        email_form_field = find_first_occurrence_in_list(
            lambda x: x.id == FORM_FIELD_EMAIL_ID, form_fields
        )
        if email_form_field is None:
            raise Exception("Should never come here")
        email = email_form_field.value

        result = await api_options.recipe_implementation.sign_up(
            email, password, tenant_id, user_context
        )

        if isinstance(result, SignUpEmailAlreadyExistsError):
            return SignUpPostEmailAlreadyExistsError()

        user = result.user
        session = await create_new_session(
            tenant_id=tenant_id,
            request=api_options.request,
            user_id=user.user_id,
            access_token_payload={},
            session_data_in_database={},
            user_context=user_context,
        )
        return SignUpPostOkResult(user, session)
