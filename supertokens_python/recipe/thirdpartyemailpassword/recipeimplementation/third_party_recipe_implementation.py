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
from typing import Union, List

from supertokens_python.recipe.thirdparty.interfaces import RecipeInterface, SignInUpOkResult, SignInUpResult
from supertokens_python.recipe.thirdpartyemailpassword.types import UsersResponse, User
from supertokens_python.recipe.thirdpartyemailpassword.interfaces import \
    RecipeInterface as ThirdPartyEmailPasswordRecipeInterface


class RecipeImplementation(RecipeInterface):

    def __init__(
            self, recipe_implementation: ThirdPartyEmailPasswordRecipeInterface):
        super().__init__()
        self.recipe_implementation = recipe_implementation

    async def get_user_by_id(self, user_id: str) -> Union[User, None]:
        user = await self.recipe_implementation.get_user_by_id(user_id)
        if user is None or user.third_party_info is None:
            return None

        return user

    async def get_users_by_email(self, email: str) -> List[User]:
        users = await self.recipe_implementation.get_users_by_email(email)
        users_result = []

        for user in users:
            if user.third_party_info is not None:
                users_result.append(user)

        return users_result

    async def get_user_by_thirdparty_info(self, third_party_id: str, third_party_user_id: str) -> Union[User, None]:
        user = await self.recipe_implementation.get_user_by_thirdparty_info(third_party_id, third_party_user_id)
        if user is None or user.third_party_info is None:
            return None

        return user

    async def sign_in_up(self, third_party_id: str, third_party_user_id: str, email: str,
                         email_verified: bool) -> SignInUpResult:
        result = await self.recipe_implementation.sign_in_up(third_party_id, third_party_user_id, email, email_verified)

        if result.user.third_party_info is None:
            raise Exception("Should never come here")

        return SignInUpOkResult(
            created_new_user=result.created_new_user, user=result.user)

    async def get_users_oldest_first(self, limit: int = None, next_pagination: str = None) -> UsersResponse:
        raise Exception("Should never come here")

    async def get_users_newest_first(self, limit: int = None, next_pagination: str = None) -> UsersResponse:
        raise Exception("Should never come here")

    async def get_user_count(self) -> int:
        raise Exception("Should never come here")
