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

from typing import TYPE_CHECKING, Union

try:
    from typing import Literal
except ImportError:
    from typing_extensions import Literal

from .interfaces import (
    RecipeInterface, SignInOkResult, SignInWrongCredentialsErrorResult, SignUpOkResult,
    SignUpEmailAlreadyExistsErrorResult, UpdateEmailOrPasswordEmailAlreadyExistsErrorResult,
    CreateResetPasswordWrongUserIdErrorResult, ResetPasswordUsingTokenOkResult,
    ResetPasswordUsingTokenWrongUserIdErrorResult, UpdateEmailOrPasswordOkResult,
    UpdateEmailOrPasswordUnknownUserIdErrorResult, CreateResetPasswordOkResult
)
from .types import User, UsersResponse
from supertokens_python.normalised_url_path import NormalisedURLPath

if TYPE_CHECKING:
    from supertokens_python.querier import Querier
    from .interfaces import (
        UpdateEmailOrPasswordResult, SignUpResult, SignInResult, ResetPasswordUsingTokenResult,
        CreateResetPasswordResult
    )


class RecipeImplementation(RecipeInterface):
    def __init__(self, querier: Querier):
        super().__init__()
        self.querier = querier

    async def get_user_by_id(self, user_id: str) -> Union[User, None]:
        params = {
            'userId': user_id
        }
        response = await self.querier.send_get_request(NormalisedURLPath('/recipe/user'), params)
        if 'status' in response and response['status'] == 'OK':
            return User(response['user']['id'], response['user']
                        ['email'], response['user']['timeJoined'])
        return None

    async def get_user_by_email(self, email: str) -> Union[User, None]:
        params = {
            'email': email
        }
        response = await self.querier.send_get_request(NormalisedURLPath('/recipe/user'), params)
        if 'status' in response and response['status'] == 'OK':
            return User(response['user']['id'], response['user']
                        ['email'], response['user']['timeJoined'])
        return None

    async def create_reset_password_token(self, user_id: str) -> CreateResetPasswordResult:
        data = {
            'userId': user_id
        }
        response = await self.querier.send_post_request(
            NormalisedURLPath('/recipe/user/password/reset/token'),
            data)
        if 'status' in response and response['status'] == 'OK':
            return CreateResetPasswordOkResult(response['token'])
        return CreateResetPasswordWrongUserIdErrorResult()

    async def reset_password_using_token(self, token: str, new_password: str) -> ResetPasswordUsingTokenResult:
        data = {
            'method': 'token',
            'token': token,
            'newPassword': new_password
        }
        response = await self.querier.send_post_request(
            NormalisedURLPath('/recipe/user/password/reset'), data)
        if 'status' not in response or response['status'] != 'OK':
            return ResetPasswordUsingTokenWrongUserIdErrorResult()
        return ResetPasswordUsingTokenOkResult()

    async def get_users(self, time_joined_order: Literal['ASC', 'DESC'],
                        limit: Union[int, None] = None, pagination_token: Union[str, None] = None) -> UsersResponse:
        params = {
            'timeJoinedOrder': time_joined_order
        }
        if limit is not None:
            params = {
                'limit': limit,
                **params
            }
        if pagination_token is not None:
            params = {
                'paginationToken': pagination_token,
                **params
            }
        response = await self.querier.send_get_request(NormalisedURLPath('/recipe/users'), params)
        next_pagination_token = None
        if 'nextPaginationToken' in response:
            next_pagination_token = response['nextPaginationToken']
        users_list = response['users']
        users = []
        for user in users_list:
            users.append(User(user['id'], user['email'], user['timeJoined']))

        return UsersResponse(users, next_pagination_token)

    async def sign_in(self, email: str, password: str) -> SignInResult:
        data = {
            'password': password,
            'email': email
        }
        response = await self.querier.send_post_request(NormalisedURLPath('/recipe/signin'), data)
        if 'status' in response and response['status'] == 'OK':
            return SignInOkResult(
                User(response['user']['id'], response['user']['email'], response['user']['timeJoined']))
        return SignInWrongCredentialsErrorResult()

    async def sign_up(self, email: str, password: str) -> SignUpResult:
        data = {
            'password': password,
            'email': email
        }
        response = await self.querier.send_post_request(NormalisedURLPath('/recipe/signup'), data)
        if 'status' in response and response['status'] == 'OK':
            return SignUpOkResult(
                User(response['user']['id'], response['user']['email'], response['user']['timeJoined']))
        return SignUpEmailAlreadyExistsErrorResult()

    async def get_users_oldest_first(self, limit: int = None, next_pagination: str = None) -> UsersResponse:
        return await self.get_users('ASC', limit, next_pagination)

    async def get_users_newest_first(self, limit: int = None, next_pagination: str = None) -> UsersResponse:
        return await self.get_users('DESC', limit, next_pagination)

    async def get_user_count(self) -> int:
        response = await self.querier.send_get_request(NormalisedURLPath('/recipe/users/count'))
        return int(response['count'])

    async def update_email_or_password(self, user_id: str, email: Union[str, None] = None,
                                       password: Union[str, None] = None) -> UpdateEmailOrPasswordResult:
        data = {
            'userId': user_id
        }
        if email is not None:
            data = {
                'email': email,
                **data
            }
        if password is not None:
            data = {
                'password': password,
                **data
            }
        response = await self.querier.send_put_request(NormalisedURLPath('/recipe/user'), data)
        if 'status' in response and response['status'] == 'OK':
            return UpdateEmailOrPasswordOkResult()
        if 'status' in response and response['status'] == 'EMAIL_ALREADY_EXISTS_ERROR':
            return UpdateEmailOrPasswordEmailAlreadyExistsErrorResult()
        return UpdateEmailOrPasswordUnknownUserIdErrorResult()
