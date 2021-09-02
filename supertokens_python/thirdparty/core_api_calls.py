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
from .types import User, UsersResponse, ThirdPartyInfo, SignInUpResponse
from typing import Union, Literal, TYPE_CHECKING
if TYPE_CHECKING:
    from .recipe import ThirdPartyRecipe


async def sign_in_up(recipe: ThirdPartyRecipe, third_party_id: str, third_party_user_id: str, email: str, email_verified: bool) -> SignInUpResponse:
    data = {
        'thirdPartyId': third_party_id,
        'thirdPartyUserId': third_party_user_id,
        'email': {
            'id': email,
            'isVerified': email_verified
        }
    }
    response = await recipe.get_querier().send_post_request(NormalisedURLPath(recipe, '/recipe/signinup'), data)
    return SignInUpResponse(
        User(
            response['user']['id'],
            response['user']['email'],
            response['user']['timeJoined'],
            ThirdPartyInfo(
                response['user']['thirdParty']['userId'],
                response['user']['thirdParty']['id']
            )
        ),
        response['createdNewUser']
    )


async def get_user_by_id(recipe: ThirdPartyRecipe, user_id: str) -> Union[User, None]:
    params = {
        'userId': user_id
    }
    response = await recipe.get_querier().send_get_request(NormalisedURLPath(recipe, '/recipe/user'), params)
    if 'status' in response and response['status'] == 'OK':
        return User(
            response['user']['id'],
            response['user']['email'],
            response['user']['timeJoined'],
            ThirdPartyInfo(
                response['user']['thirdParty']['userId'],
                response['user']['thirdParty']['id']
            )
        )
    return None


async def get_user_by_third_party_info(recipe: ThirdPartyRecipe, third_party_id: str, third_party_user_id: str) -> Union[User, None]:
    params = {
        'thirdPartyId': third_party_id,
        'thirdPartyUserId': third_party_user_id
    }
    response = await recipe.get_querier().send_get_request(NormalisedURLPath(recipe, '/recipe/user'), params)
    if 'status' in response and response['status'] == 'OK':
        return User(
            response['user']['id'],
            response['user']['email'],
            response['user']['timeJoined'],
            ThirdPartyInfo(
                response['user']['thirdParty']['userId'],
                response['user']['thirdParty']['id']
            )
        )
    return None


async def get_users(recipe: ThirdPartyRecipe, time_joined_order: Literal['ASC', 'DESC'],
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
        users.append(
            User(
                user['id'],
                user['email'],
                user['timeJoined'],
                ThirdPartyInfo(
                    user['thirdParty']['userId'],
                    user['thirdParty']['id']
                )
            )
        )

    return UsersResponse(users, next_pagination_token)


async def get_users_count(recipe: ThirdPartyRecipe) -> int:
    response = await recipe.get_querier().send_get_request(NormalisedURLPath(recipe, '/recipe/users/count'))
    return int(response['count'])
