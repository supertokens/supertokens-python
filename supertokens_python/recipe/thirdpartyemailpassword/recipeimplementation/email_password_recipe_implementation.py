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
from typing import Union

from supertokens_python.recipe.emailpassword.interfaces import RecipeInterface, UpdateEmailOrPasswordResult, \
    SignUpResult, SignInResult, ResetPasswordUsingTokenResult, CreateResetPasswordResult
from supertokens_python.recipe.emailpassword.types import UsersResponse, User
from supertokens_python.recipe.thirdpartyemailpassword.interfaces import \
    RecipeInterface as ThirdPartyEmailPasswordRecipeInterface


class RecipeImplementation(RecipeInterface):

    def __init__(
            self, recipe_implementation: ThirdPartyEmailPasswordRecipeInterface):
        super().__init__()
        self.recipe_implementation = recipe_implementation

    async def get_user_by_id(self, user_id: str) -> Union[User, None]:
        user = await self.recipe_implementation.get_user_by_id(user_id)

        if user is None or user.third_party_info is not None:
            return None

        return user

    async def get_user_by_email(self, email: str) -> Union[User, None]:
        results = await self.recipe_implementation.get_users_by_email(email)

        for result in results:
            if result.third_party_info is None:
                return result

        return None

    async def create_reset_password_token(self, user_id: str) -> CreateResetPasswordResult:
        return await self.recipe_implementation.create_reset_password_token(user_id)

    async def reset_password_using_token(self, token: str, new_password: str) -> ResetPasswordUsingTokenResult:
        return await self.recipe_implementation.reset_password_using_token(token, new_password)

    async def sign_in(self, email: str, password: str) -> SignInResult:
        return await self.recipe_implementation.sign_in(email, password)

    async def sign_up(self, email: str, password: str) -> SignUpResult:
        return await self.recipe_implementation.sign_up(email, password)

    async def get_users_oldest_first(self, limit: int = None, next_pagination: str = None) -> UsersResponse:
        raise Exception("Should never be called")

    async def get_users_newest_first(self, limit: int = None, next_pagination: str = None) -> UsersResponse:
        raise Exception("Should never be called")

    async def get_user_count(self) -> int:
        raise Exception("Should never be called")

    async def update_email_or_password(self, user_id: str, email: Union[str, None] = None,
                                       password: Union[str, None] = None) -> UpdateEmailOrPasswordResult:
        return await self.recipe_implementation.update_password_or_email(user_id, email, password)
