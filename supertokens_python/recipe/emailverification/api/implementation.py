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

from typing import TYPE_CHECKING, Any, Dict, Union, Optional

from supertokens_python.logger import log_debug_message
from supertokens_python.recipe.emailverification import (
    EmailVerificationRecipe,
    EmailVerificationClaim,
)
from supertokens_python.recipe.emailverification.interfaces import (
    APIInterface,
    CreateEmailVerificationTokenEmailAlreadyVerifiedError,
    EmailVerifyPostInvalidTokenError,
    EmailVerifyPostOkResult,
    GenerateEmailVerifyTokenPostEmailAlreadyVerifiedError,
    GenerateEmailVerifyTokenPostOkResult,
    IsEmailVerifiedGetOkResult,
    VerifyEmailUsingTokenOkResult,
    EmailDoesnotExistError,
    GetEmailForUserIdOkResult,
)
from supertokens_python.recipe.session.interfaces import SessionContainer

if TYPE_CHECKING:
    from supertokens_python.recipe.emailverification.interfaces import APIOptions

from supertokens_python.recipe.emailverification.types import (
    VerificationEmailTemplateVarsUser,
    VerificationEmailTemplateVars,
)


class APIImplementation(APIInterface):
    async def email_verify_post(
        self,
        token: str,
        api_options: APIOptions,
        user_context: Dict[str, Any],
        session: Optional[SessionContainer] = None,
    ) -> Union[EmailVerifyPostOkResult, EmailVerifyPostInvalidTokenError]:
        response = await api_options.recipe_implementation.verify_email_using_token(
            token, user_context
        )
        if isinstance(response, VerifyEmailUsingTokenOkResult):
            if session is not None:
                await session.fetch_and_set_claim(EmailVerificationClaim, user_context)

            return EmailVerifyPostOkResult(response.user)
        return EmailVerifyPostInvalidTokenError()

    async def is_email_verified_get(
        self,
        api_options: APIOptions,
        user_context: Dict[str, Any],
        session: Optional[SessionContainer] = None,
    ) -> IsEmailVerifiedGetOkResult:
        if session is None:
            raise Exception("Session is undefined. Should not come here.")
        await session.fetch_and_set_claim(EmailVerificationClaim, user_context)
        is_verified = await session.get_claim_value(
            EmailVerificationClaim, user_context
        )
        # TODO: Type of is_verified should be bool. It's any for now.

        if is_verified is None:
            raise Exception(
                "Should never come here: EmailVerificationClaim failed to set value"
            )

        return IsEmailVerifiedGetOkResult(is_verified)

    async def generate_email_verify_token_post(
        self,
        api_options: APIOptions,
        user_context: Dict[str, Any],
        session: SessionContainer,
    ) -> Union[
        GenerateEmailVerifyTokenPostOkResult,
        GenerateEmailVerifyTokenPostEmailAlreadyVerifiedError,
    ]:
        if session is None:
            raise Exception("Session is undefined. Should not come here.")

        user_id = session.get_user_id(user_context)
        email_info = await EmailVerificationRecipe.get_instance().get_email_for_user_id(
            user_id, user_context
        )

        if isinstance(email_info, EmailDoesnotExistError):
            log_debug_message(
                "Email verification email not sent to user %s because it doesn't have an email address.",
                user_id,
            )
            return GenerateEmailVerifyTokenPostEmailAlreadyVerifiedError()
        if isinstance(email_info, GetEmailForUserIdOkResult):
            response = (
                await api_options.recipe_implementation.create_email_verification_token(
                    user_id,
                    email_info.email,
                    user_context,
                )
            )

            if isinstance(
                response, CreateEmailVerificationTokenEmailAlreadyVerifiedError
            ):
                log_debug_message(
                    "Email verification email not sent to %s because it is already verified.",
                    email_info.email,
                )
                return GenerateEmailVerifyTokenPostEmailAlreadyVerifiedError()

            email_verify_link = (
                api_options.app_info.website_domain.get_as_string_dangerous()
                + api_options.app_info.website_base_path.get_as_string_dangerous()
                + "/verify-email/"
                + "?token="
                + response.token
                + "&rid="
                + api_options.recipe_id
            )

            log_debug_message("Sending email verification email to %s", email_info)
            email_verification_email_delivery_input = VerificationEmailTemplateVars(
                user=VerificationEmailTemplateVarsUser(user_id, email_info.email),
                email_verify_link=email_verify_link,
                user_context=user_context,
            )
            await api_options.email_delivery.ingredient_interface_impl.send_email(
                email_verification_email_delivery_input, user_context
            )
            return GenerateEmailVerifyTokenPostOkResult()

        raise Exception(
            "Should never come here: UNKNOWN_USER_ID or invalid result from get_email_for_user_id"
        )
