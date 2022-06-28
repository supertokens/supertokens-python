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

from typing import TYPE_CHECKING, Any, Dict, Union

from supertokens_python.logger import log_debug_message
from supertokens_python.recipe.emailverification.interfaces import (
    APIInterface,
    CreateEmailVerificationTokenEmailAlreadyVerifiedError,
    EmailVerifyPostInvalidTokenError,
    EmailVerifyPostOkResult,
    GenerateEmailVerifyTokenPostEmailAlreadyVerifiedError,
    GenerateEmailVerifyTokenPostOkResult,
    IsEmailVerifiedGetOkResult,
    VerifyEmailUsingTokenOkResult,
)

if TYPE_CHECKING:
    from supertokens_python.recipe.emailverification.interfaces import APIOptions

from supertokens_python.recipe.emailverification.types import (
    User,
    VerificationEmailTemplateVarsUser,
    VerificationEmailTemplateVars,
)
from supertokens_python.recipe.session.asyncio import get_session


class APIImplementation(APIInterface):
    async def email_verify_post(
        self, token: str, api_options: APIOptions, user_context: Dict[str, Any]
    ) -> Union[EmailVerifyPostOkResult, EmailVerifyPostInvalidTokenError]:
        response = await api_options.recipe_implementation.verify_email_using_token(
            token, user_context
        )
        if isinstance(response, VerifyEmailUsingTokenOkResult):
            return EmailVerifyPostOkResult(response.user)
        return EmailVerifyPostInvalidTokenError()

    async def is_email_verified_get(
        self, api_options: APIOptions, user_context: Dict[str, Any]
    ) -> IsEmailVerifiedGetOkResult:
        session = await get_session(api_options.request)
        if session is None:
            raise Exception("Session is undefined. Should not come here.")

        user_id = session.get_user_id(user_context)
        email = await api_options.config.get_email_for_user_id(user_id, user_context)

        is_verified = await api_options.recipe_implementation.is_email_verified(
            user_id, email, user_context
        )
        return IsEmailVerifiedGetOkResult(is_verified)

    async def generate_email_verify_token_post(
        self, api_options: APIOptions, user_context: Dict[str, Any]
    ) -> Union[
        GenerateEmailVerifyTokenPostOkResult,
        GenerateEmailVerifyTokenPostEmailAlreadyVerifiedError,
    ]:
        session = await get_session(api_options.request)
        if session is None:
            raise Exception("Session is undefined. Should not come here.")

        user_id = session.get_user_id(user_context)
        email = await api_options.config.get_email_for_user_id(user_id, user_context)

        token_result = (
            await api_options.recipe_implementation.create_email_verification_token(
                user_id, email, user_context
            )
        )
        if isinstance(
            token_result, CreateEmailVerificationTokenEmailAlreadyVerifiedError
        ):
            log_debug_message(
                "Email verification email not sent to %s because it is already verified",
                email,
            )
            return GenerateEmailVerifyTokenPostEmailAlreadyVerifiedError()

        user = User(user_id, email)

        email_verify_link = (
            (await api_options.config.get_email_verification_url(user, user_context))
            + "?token="
            + token_result.token
            + "&rid="
            + api_options.recipe_id
        )

        log_debug_message("Sending email verification email to %s", email)
        email_delivery_user = VerificationEmailTemplateVarsUser(
            user.user_id, user.email
        )
        email_verification_email_delivery_input = VerificationEmailTemplateVars(
            user=email_delivery_user,
            email_verify_link=email_verify_link,
            user_context=user_context,
        )
        await api_options.email_delivery.ingredient_interface_impl.send_email(
            email_verification_email_delivery_input, user_context
        )

        return GenerateEmailVerifyTokenPostOkResult()
