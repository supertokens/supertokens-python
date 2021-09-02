"""
Copyright (c) 2021, VRAI Labs and/or its affiliates. All rights reserved.

This software is licensed under the Apache License, Version 2.0 (the
"License") as published by the Apache Software Foundation.

You may not use this file except in compliance with the License. You may
obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.
"""
from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .recipe import EmailVerificationRecipe
from supertokens_python.normalised_url_path import NormalisedURLPath
from .types import User
from .exceptions import (
    raise_email_already_verified_exception,
    raise_email_verification_invalid_token_exception
)


async def create_email_verification_token(recipe: EmailVerificationRecipe, user_id: str, email: str) -> str:
    data = {
        'userId': user_id,
        'email': email
    }
    response = await recipe.get_querier().send_post_request(NormalisedURLPath(recipe, '/recipe/user/email/verify/token'), data)
    if 'status' in response and response['status'] == 'OK':
        return response['token']
    raise_email_already_verified_exception(recipe,
                                           'Failed to generated email verification token as the email is already '
                                           'verified')


async def verify_email_using_token(recipe: EmailVerificationRecipe, token: str) -> User:
    data = {
        'method': 'token',
        'token': token
    }
    response = await recipe.get_querier().send_post_request(NormalisedURLPath(recipe, '/recipe/user/email/verify'), data)
    if 'status' in response and response['status'] == 'OK':
        return User(response['userId'], response['email'])
    raise_email_verification_invalid_token_exception(recipe, 'Failed to verify email as the the token has expired or is invalid')


async def is_email_verified(recipe: EmailVerificationRecipe, user_id: str, email: str) -> bool:
    params = {
        'userId': user_id,
        'email': email
    }
    response = await recipe.get_querier().send_get_request(NormalisedURLPath(recipe, '/recipe/user/email/verify'), params)
    return response['isVerified']
