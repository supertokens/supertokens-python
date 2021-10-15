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
from .interfaces import (
    RecipeInterface, UnverifyEmailResult, RevokeEmailVerificationTokensResult,
    VerifyEmailUsingTokenResult, CreateEmailVerificationTokenResult,
    UnverifyEmailOkResult, CreateEmailVerificationTokenEmailAlreadyVerifiedErrorResult,
    CreateEmailVerificationTokenOkResult, VerifyEmailUsingTokenInvalidTokenErrorResult,
    VerifyEmailUsingTokenOkResult, RevokeEmailVerificationTokensOkResult
)
from typing import TYPE_CHECKING

from .types import User
from supertokens_python.normalised_url_path import NormalisedURLPath

if TYPE_CHECKING:
    from .utils import EmailVerificationConfig
    from supertokens_python.querier import Querier


class RecipeImplementation(RecipeInterface):
    def __init__(self, querier: Querier, config: EmailVerificationConfig):
        super().__init__()
        self.querier = querier
        self.config = config

    async def create_email_verification_token(self, user_id: str, email: str) -> CreateEmailVerificationTokenResult:
        data = {
            'userId': user_id,
            'email': email
        }
        response = await self.querier.send_post_request(NormalisedURLPath('/recipe/user/email/verify/token'), data)
        if 'status' in response and response['status'] == 'OK':
            return CreateEmailVerificationTokenOkResult(response['token'])
        return CreateEmailVerificationTokenEmailAlreadyVerifiedErrorResult()

    async def verify_email_using_token(self, token: str) -> VerifyEmailUsingTokenResult:
        data = {
            'method': 'token',
            'token': token
        }
        response = await self.querier.send_post_request(NormalisedURLPath('/recipe/user/email/verify'), data)
        if 'status' in response and response['status'] == 'OK':
            return VerifyEmailUsingTokenOkResult(
                User(response['userId'], response['email']))
        return VerifyEmailUsingTokenInvalidTokenErrorResult()

    async def is_email_verified(self, user_id: str, email: str) -> bool:
        params = {
            'userId': user_id,
            'email': email
        }
        response = await self.querier.send_get_request(NormalisedURLPath('/recipe/user/email/verify'), params)
        return response['isVerified']

    async def revoke_email_verification_tokens(self, user_id: str, email: str) -> RevokeEmailVerificationTokensResult:
        data = {
            'userId': user_id,
            'email': email
        }
        await self.querier.send_post_request(NormalisedURLPath('/recipe/user/email/verify/token/remove'), data)
        return RevokeEmailVerificationTokensOkResult()

    async def unverify_email(self, user_id: str, email: str) -> UnverifyEmailResult:
        data = {
            'userId': user_id,
            'email': email
        }
        await self.querier.send_post_request(NormalisedURLPath('/recipe/user/email/verify/remove'), data)
        return UnverifyEmailOkResult()
