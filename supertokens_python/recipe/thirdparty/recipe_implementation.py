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

from typing import TYPE_CHECKING, Union, List

try:
    from typing import Literal
except ImportError:
    from typing_extensions import Literal

from supertokens_python.normalised_url_path import NormalisedURLPath

if TYPE_CHECKING:
    from supertokens_python.querier import Querier
    from .interfaces import SignInUpResult
from .types import User, UsersResponse, ThirdPartyInfo
from .interfaces import (
    RecipeInterface, SignInUpOkResult
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

    async def get_users_by_email(self, email: str) -> List[User]:
        response = await self.querier.send_get_request(NormalisedURLPath('/recipe/users/by-email'), {'email': email})
        users = []
        users_list = response['users'] if 'users' in response else []
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
        return users

    async def get_user_by_thirdparty_info(self, third_party_id: str, third_party_user_id: str) -> Union[User, None]:
        params = {
            'thirdPartyId': third_party_id,
            'thirdPartyUserId': third_party_user_id
        }
        response = await self.querier.send_get_request(NormalisedURLPath('/recipe/user'), params)
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

    async def sign_in_up(self, third_party_id: str, third_party_user_id: str, email: str,
                         email_verified: bool) -> SignInUpResult:
        data = {
            'thirdPartyId': third_party_id,
            'thirdPartyUserId': third_party_user_id,
            'email': {
                'id': email,
                'isVerified': email_verified
            }
        }
        response = await self.querier.send_post_request(NormalisedURLPath('/recipe/signinup'), data)
        return SignInUpOkResult(
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

    async def get_users_oldest_first(self, limit: int = None, next_pagination: str = None) -> UsersResponse:
        return await self.get_users('ASC', limit, next_pagination)

    async def get_users_newest_first(self, limit: int = None, next_pagination: str = None) -> UsersResponse:
        return await self.get_users('DESC', limit, next_pagination)

    async def get_user_count(self) -> int:
        response = await self.querier.send_get_request(NormalisedURLPath('/recipe/users/count'))
        return int(response['count'])

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
