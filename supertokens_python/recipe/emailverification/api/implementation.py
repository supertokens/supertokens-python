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

from supertokens_python.recipe.emailverification.interfaces import (
    APIInterface, CreateEmailVerificationTokenEmailAlreadyVerifiedErrorResult,
    EmailVerifyPostInvalidTokenErrorResponse, EmailVerifyPostOkResponse,
    GenerateEmailVerifyTokenPostEmailAlreadyVerifiedErrorResponse,
    GenerateEmailVerifyTokenPostOkResponse, IsEmailVerifiedGetOkResponse,
    VerifyEmailUsingTokenOkResult)

if TYPE_CHECKING:
    from supertokens_python.recipe.emailverification.interfaces import (
        APIOptions
    )

from supertokens_python.recipe.emailverification.types import User
from supertokens_python.recipe.session.asyncio import get_session


class APIImplementation(APIInterface):
    async def email_verify_post(self, token: str, api_options: APIOptions, user_context: Dict[str, Any]) -> Union[EmailVerifyPostOkResponse, EmailVerifyPostInvalidTokenErrorResponse]:
        """email_verify_post is an async method that accepts

               - token: string,
               - api_options: APIOptions,
               - user_context: python dict

            if the user is successfully verified the method returns an instance of EmailVerifyPostOkResponse.

            If the token is invalid and the user is not verified it returns an instance of EmailVerifyPostInvalidTokenErrorResponse.
        """

        response = await api_options.recipe_implementation.verify_email_using_token(token, user_context)
        if isinstance(response, VerifyEmailUsingTokenOkResult):
            return EmailVerifyPostOkResponse(response.user)
        return EmailVerifyPostInvalidTokenErrorResponse()

    async def is_email_verified_get(self, api_options: APIOptions, user_context: Dict[str, Any]) -> IsEmailVerifiedGetOkResponse:
        """
        is_email_verified_get is an async method that accepts

            - api_options: APIOptions
            - user_context: Dict

        Upon the successful verification this method returns an instance of IsEmailVerifiedGetOkResponse.

        In the case of failure during verification this method raises an Exception.
        """

        # TODO: fix docstring, docstring should mention exact functioning of this method.
        # TODO: this method should return an error response instead of an exception.

        session = await get_session(api_options.request)

        if session:
            user_id = session.get_user_id(user_context)
            email = await api_options.config.get_email_for_user_id(user_id, user_context)
            is_verified = await api_options.recipe_implementation.is_email_verified(user_id, email, user_context)
            return IsEmailVerifiedGetOkResponse(is_verified)

        raise Exception("Undefined Session")

    async def generate_email_verify_token_post(self, api_options: APIOptions, user_context: Dict[str, Any]) -> Union[GenerateEmailVerifyTokenPostOkResponse, GenerateEmailVerifyTokenPostEmailAlreadyVerifiedErrorResponse]:
        """
        generate_email_verify_token_post is an async method that accepts

            - api_options: APIOptions
            - user_context: Dict

        This method returns an instance of GenerateEmailVerifyTokenPostOkResponse class
        if the verification token for the given email id is successfully generated.

        It returns an instance of GenerateEmailVerifyTokenPostEmailAlreadyVerifiedErrorResponse
        if the email id is already verified.

        It raises an exception otherwise.
        #TODO: need to handle this gracefully
        """
        session = await get_session(api_options.request)
        if session:
            user_id = session.get_user_id(user_context)
            email = await api_options.config.get_email_for_user_id(user_id, user_context)

            token_result = await api_options.recipe_implementation.create_email_verification_token(user_id, email, user_context)
            if isinstance(token_result, CreateEmailVerificationTokenEmailAlreadyVerifiedErrorResult):
                return GenerateEmailVerifyTokenPostEmailAlreadyVerifiedErrorResponse()

            user = User(user_id, email)

            # TODO: This validation is unnecessary since CreateEmailVerificationTokenOkResult needs a valid token.
            if token_result.token:
                email_verify_link = (await api_options.config.get_email_verification_url(
                    user, user_context)) + '?token=' + token_result.token + '&rid' + api_options.recipe_id

                try:
                    await api_options.config.create_and_send_custom_email(user, email_verify_link, user_context)
                except Exception:
                    pass
                return GenerateEmailVerifyTokenPostOkResponse()

        raise Exception('Undefined Session')
