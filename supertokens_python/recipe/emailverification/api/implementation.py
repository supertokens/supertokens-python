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

from supertokens_python.recipe.emailverification.interfaces import (
    APIInterface, EmailVerifyPostInvalidTokenErrorResponse,
    EmailVerifyPostOkResponse, GenerateEmailVerifyTokenPostEmailAlreadyVerifiedErrorResponse,
    GenerateEmailVerifyTokenPostOkResponse, IsEmailVerifiedGetOkResponse
)

if TYPE_CHECKING:
    from supertokens_python.recipe.emailverification.interfaces import (
        APIOptions, GenerateEmailVerifyTokenPostResponse, IsEmailVerifiedGetResponse, EmailVerifyPostResponse
    )
from supertokens_python.recipe.emailverification.types import User
from supertokens_python.recipe.session.asyncio import get_session


class APIImplementation(APIInterface):
    def __init__(self):
        super().__init__()

    async def email_verify_post(self, token: str, api_options: APIOptions) -> EmailVerifyPostResponse:
        response = await api_options.recipe_implementation.verify_email_using_token(token)
        if response.is_ok:
            return EmailVerifyPostOkResponse(response.user)
        return EmailVerifyPostInvalidTokenErrorResponse()

    async def is_email_verified_get(self, api_options: APIOptions) -> IsEmailVerifiedGetResponse:
        session = await get_session(api_options.request)
        if session is None:
            raise Exception('Session is undefined. Should not come here.')

        user_id = session.get_user_id()
        email = await api_options.config.get_email_for_user_id(user_id)

        is_verified = await api_options.recipe_implementation.is_email_verified(user_id, email)
        return IsEmailVerifiedGetOkResponse(is_verified)

    async def generate_email_verify_token_post(self, api_options: APIOptions) -> GenerateEmailVerifyTokenPostResponse:
        session = await get_session(api_options.request)
        if session is None:
            raise Exception('Session is undefined. Should not come here.')

        user_id = session.get_user_id()
        email = await api_options.config.get_email_for_user_id(user_id)

        token_result = await api_options.recipe_implementation.create_email_verification_token(user_id, email)
        if token_result.is_email_already_verified:
            return GenerateEmailVerifyTokenPostEmailAlreadyVerifiedErrorResponse()

        user = User(user_id, email)

        email_verify_link = (await api_options.config.get_email_verification_url(
            user)) + '?token=' + token_result.token + '&rid' + api_options.recipe_id

        try:
            await api_options.config.create_and_send_custom_email(user, email_verify_link)
        except Exception:
            pass

        return GenerateEmailVerifyTokenPostOkResponse()
