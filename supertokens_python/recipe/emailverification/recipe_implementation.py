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

from typing import TYPE_CHECKING, Any, Dict

from supertokens_python.normalised_url_path import NormalisedURLPath

from .interfaces import (
    CreateEmailVerificationTokenEmailAlreadyVerifiedErrorResult,
    CreateEmailVerificationTokenOkResult, CreateEmailVerificationTokenResult,
    RecipeInterface, RevokeEmailVerificationTokensOkResult,
    RevokeEmailVerificationTokensResult, UnverifyEmailOkResult,
    UnverifyEmailResult, VerifyEmailUsingTokenInvalidTokenErrorResult,
    VerifyEmailUsingTokenOkResult, VerifyEmailUsingTokenResult)
from .types import User

if TYPE_CHECKING:
    from supertokens_python.querier import Querier

    from .utils import EmailVerificationConfig


class RecipeImplementation(RecipeInterface):
    """RecipeImplementation.
    """

    def __init__(self, querier: Querier, config: EmailVerificationConfig):
        """__init__.

        Parameters
        ----------
        querier : Querier
            querier
        config : EmailVerificationConfig
            config
        """
        super().__init__()
        self.querier = querier
        self.config = config

    async def create_email_verification_token(self, user_id: str, email: str, user_context: Dict[str, Any]) -> CreateEmailVerificationTokenResult:
        """create_email_verification_token.

        Parameters
        ----------
        user_id : str
            user_id
        email : str
            email
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        CreateEmailVerificationTokenResult

        """
        data = {
            'userId': user_id,
            'email': email
        }
        response = await self.querier.send_post_request(NormalisedURLPath('/recipe/user/email/verify/token'), data)
        if 'status' in response and response['status'] == 'OK':
            return CreateEmailVerificationTokenOkResult(response['token'])
        return CreateEmailVerificationTokenEmailAlreadyVerifiedErrorResult()

    async def verify_email_using_token(self, token: str, user_context: Dict[str, Any]) -> VerifyEmailUsingTokenResult:
        """verify_email_using_token.

        Parameters
        ----------
        token : str
            token
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        VerifyEmailUsingTokenResult

        """
        data = {
            'method': 'token',
            'token': token
        }
        response = await self.querier.send_post_request(NormalisedURLPath('/recipe/user/email/verify'), data)
        if 'status' in response and response['status'] == 'OK':
            return VerifyEmailUsingTokenOkResult(
                User(response['userId'], response['email']))
        return VerifyEmailUsingTokenInvalidTokenErrorResult()

    async def is_email_verified(self, user_id: str, email: str, user_context: Dict[str, Any]) -> bool:
        """is_email_verified.

        Parameters
        ----------
        user_id : str
            user_id
        email : str
            email
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        bool

        """
        params = {
            'userId': user_id,
            'email': email
        }
        response = await self.querier.send_get_request(NormalisedURLPath('/recipe/user/email/verify'), params)
        return response['isVerified']

    async def revoke_email_verification_tokens(self, user_id: str, email: str, user_context: Dict[str, Any]) -> RevokeEmailVerificationTokensResult:
        """revoke_email_verification_tokens.

        Parameters
        ----------
        user_id : str
            user_id
        email : str
            email
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        RevokeEmailVerificationTokensResult

        """
        data = {
            'userId': user_id,
            'email': email
        }
        await self.querier.send_post_request(NormalisedURLPath('/recipe/user/email/verify/token/remove'), data)
        return RevokeEmailVerificationTokensOkResult()

    async def unverify_email(self, user_id: str, email: str, user_context: Dict[str, Any]) -> UnverifyEmailResult:
        """unverify_email.

        Parameters
        ----------
        user_id : str
            user_id
        email : str
            email
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        UnverifyEmailResult

        """
        data = {
            'userId': user_id,
            'email': email
        }
        await self.querier.send_post_request(NormalisedURLPath('/recipe/user/email/verify/remove'), data)
        return UnverifyEmailOkResult()
