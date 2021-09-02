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
from supertokens_python.normalised_url_path import NormalisedURLPath
from .types import User, UsersResponse
from .exceptions import (
    raise_email_already_exists_exception,
    raise_wrong_credentials_exception,
    raise_unknown_user_id_exception,
    raise_reset_password_invalid_token_exception
)
from typing import Union, Literal, TYPE_CHECKING
if TYPE_CHECKING:
    from .recipe import EmailPasswordRecipe


async def sign_up(recipe: EmailPasswordRecipe, email: str, password: str) -> User:
    data = {
        'password': password,
        'email': email
    }
    response = await recipe.get_querier().send_post_request(NormalisedURLPath(recipe, '/recipe/signup'), data)
    if 'status' in response and response['status'] == 'OK':
        return User(response['user']['id'], response['user']['email'], response['user']['timeJoined'])
    raise_email_already_exists_exception(recipe, 'Sign up failed because the email, ' + email + ', is already taken')


async def sign_in(recipe: EmailPasswordRecipe, email: str, password: str) -> User:
    data = {
        'password': password,
        'email': email
    }
    response = await recipe.get_querier().send_post_request(NormalisedURLPath(recipe, '/recipe/signin'), data)
    if 'status' in response and response['status'] == 'OK':
        return User(response['user']['id'], response['user']['email'], response['user']['timeJoined'])
    raise_wrong_credentials_exception(recipe, 'Sign in failed because of incorrect email & password combination')


async def get_user_by_id(recipe: EmailPasswordRecipe, user_id: str) -> Union[User, None]:
    params = {
        'userId': user_id
    }
    response = await recipe.get_querier().send_get_request(NormalisedURLPath(recipe, '/recipe/user'), params)
    if 'status' in response and response['status'] == 'OK':
        return User(response['user']['id'], response['user']['email'], response['user']['timeJoined'])
    return None


async def get_user_by_email(recipe: EmailPasswordRecipe, email: str) -> Union[User, None]:
    params = {
        'email': email
    }
    response = await recipe.get_querier().send_get_request(NormalisedURLPath(recipe, '/recipe/user'), params)
    if 'status' in response and response['status'] == 'OK':
        return User(response['user']['id'], response['user']['email'], response['user']['timeJoined'])
    return None


async def create_reset_password_token(recipe: EmailPasswordRecipe, user_id: str) -> str:
    data = {
        'userId': user_id
    }
    response = await recipe.get_querier().send_post_request(NormalisedURLPath(recipe, '/recipe/user/password/reset/token'),
                                                            data)
    if 'status' in response and response['status'] == 'OK':
        return response['token']
    raise_unknown_user_id_exception(recipe, 'Failed to generated password reset token as the user ID is unknown')


async def reset_password_using_token(recipe: EmailPasswordRecipe, token: str, new_password: str) -> str:
    data = {
        'method': 'token',
        'token': token,
        'newPassword': new_password
    }
    response = await recipe.get_querier().send_post_request(NormalisedURLPath(recipe, '/recipe/user/password/reset'), data)
    if 'status' not in response or response['status'] != 'OK':
        raise_reset_password_invalid_token_exception(recipe,
                                                     'Failed to reset password as the the token has expired or is '
                                                     'invalid')


async def get_users(recipe: EmailPasswordRecipe, time_joined_order: Literal['ASC', 'DESC'],
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
    response = await recipe.get_querier().send_get_request(NormalisedURLPath(recipe, '/recipe/users'), params)
    next_pagination_token = None
    if 'nextPaginationToken' in response:
        next_pagination_token = response['nextPaginationToken']
    users_list = response['users']
    users = []
    for user in users_list:
        users.append(User(user['id'], user['email'], user['timeJoined']))

    return UsersResponse(users, next_pagination_token)


async def get_users_count(recipe: EmailPasswordRecipe) -> int:
    response = await recipe.get_querier().send_get_request(NormalisedURLPath(recipe, '/recipe/users/count'))
    return int(response['count'])
