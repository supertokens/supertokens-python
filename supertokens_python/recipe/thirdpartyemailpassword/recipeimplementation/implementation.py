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

from deprecated.classic import deprecated

from ..types import User, UsersResponse, NextPaginationToken
from ..utils import extract_pagination_token, combine_pagination_results
from supertokens_python.recipe.emailpassword.interfaces import UpdateEmailOrPasswordResult, \
    ResetPasswordUsingTokenResult, \
    CreateResetPasswordResult, SignUpResult, SignInResult
from ...thirdparty.interfaces import SignInUpResult

if TYPE_CHECKING:
    from supertokens_python.querier import Querier
from ..interfaces import (
    RecipeInterface
)
from supertokens_python.recipe.emailpassword.recipe_implementation import RecipeImplementation as EmailPasswordImplementation
from supertokens_python.recipe.thirdparty.recipe_implementation import RecipeImplementation as ThirdPartyImplementation
from .email_password_recipe_implementation import RecipeImplementation as DerivedEmailPasswordImplementation
from .third_party_recipe_implementation import RecipeImplementation as DerivedThirdPartyImplementation


class RecipeImplementation(RecipeInterface):
    def __init__(self, emailpassword_querier: Querier,
                 thirdparty_querier: Union[Querier, None]):
        super().__init__()
        emailpassword_implementation = EmailPasswordImplementation(emailpassword_querier)
        self.ep_get_user_by_id = emailpassword_implementation.get_user_by_id
        self.ep_get_user_by_email = emailpassword_implementation.get_user_by_email
        self.ep_create_reset_password_token = emailpassword_implementation.create_reset_password_token
        self.ep_reset_password_using_token = emailpassword_implementation.reset_password_using_token
        self.ep_sign_in = emailpassword_implementation.sign_in
        self.ep_sign_up = emailpassword_implementation.sign_up
        self.ep_get_users_oldest_first = emailpassword_implementation.get_users_oldest_first
        self.ep_get_users_newest_first = emailpassword_implementation.get_users_newest_first
        self.ep_get_user_count = emailpassword_implementation.get_user_count
        self.ep_update_email_or_password = emailpassword_implementation.update_email_or_password
        emailpassword_implementation = DerivedEmailPasswordImplementation(self)
        self.tp_get_user_by_id = None
        self.tp_get_users_by_email = None
        self.tp_get_user_by_thirdparty_info = None
        self.tp_sign_in_up = None
        self.tp_get_users_oldest_first = None
        self.tp_get_users_newest_first = None
        self.tp_get_user_count = None
        if thirdparty_querier is not None:
            thirdparty_implementation = ThirdPartyImplementation(
                thirdparty_querier)
            self.tp_get_user_by_id = thirdparty_implementation.get_user_by_id
            self.tp_get_users_by_email = thirdparty_implementation.get_users_by_email
            self.tp_get_user_by_thirdparty_info = thirdparty_implementation.get_user_by_thirdparty_info
            self.tp_sign_in_up = thirdparty_implementation.sign_in_up
            self.tp_get_users_oldest_first = thirdparty_implementation.get_users_oldest_first
            self.tp_get_users_newest_first = thirdparty_implementation.get_users_newest_first
            self.tp_get_user_count = thirdparty_implementation.get_user_count
            thirdparty_implementation = DerivedThirdPartyImplementation(self)

    async def get_user_by_id(self, user_id: str) -> Union[User, None]:
        user = await self.ep_get_user_by_id(user_id)

        if user is not None:
            return user
        if self.tp_get_user_by_id is None:
            return None

        return await self.tp_get_user_by_id(user_id)

    async def get_users_by_email(self, email: str) -> List[User]:
        user = await self.ep_get_user_by_email(email)

        if self.tp_get_users_by_email is None:
            return [user] if user is not None else []

        users = await self.tp_get_users_by_email(email)

        if user is not None:
            users.append(user)

        return users

    async def get_user_by_thirdparty_info(self, third_party_id: str, third_party_user_id: str) -> Union[User, None]:
        return await self.tp_get_user_by_thirdparty_info(third_party_id, third_party_user_id)

    async def sign_in_up(self, third_party_id: str, third_party_user_id: str, email: str,
                         email_verified: bool) -> SignInUpResult:
        return await self.tp_sign_in_up(third_party_id, third_party_user_id, email, email_verified)

    async def sign_in(self, email: str, password: str) -> SignInResult:
        return await self.ep_sign_in(email, password)

    async def sign_up(self, email: str, password: str) -> SignUpResult:
        return await self.ep_sign_up(email, password)

    async def create_reset_password_token(self, user_id: str) -> CreateResetPasswordResult:
        return await self.ep_create_reset_password_token(user_id)

    async def reset_password_using_token(self, token: str, new_password: str) -> ResetPasswordUsingTokenResult:
        return await self.ep_reset_password_using_token(token, new_password)

    async def update_email_or_password(self, user_id: str, email: str = None,
                                       password: str = None) -> UpdateEmailOrPasswordResult:
        return await self.ep_update_email_or_password(user_id, email, password)

    @deprecated(reason="This method is deprecated")
    async def get_users_oldest_first(self, limit: int = None, next_pagination: str = None) -> UsersResponse:
        if limit is None:
            limit = 100
        next_pagination_tokens = NextPaginationToken('null', 'null')
        if next_pagination is not None:
            next_pagination_tokens = extract_pagination_token(next_pagination)
        email_password_result_promise = self.ep_get_users_oldest_first(limit, next_pagination_tokens.email_password_pagination_token)
        third_party_result = UsersResponse([], None) if self.tp_get_users_oldest_first is None else await self.tp_get_users_oldest_first(
            limit, next_pagination_tokens.third_party_pagination_token)
        email_password_result = await email_password_result_promise
        return combine_pagination_results(
            third_party_result, email_password_result, limit, True)

    @deprecated(reason="This method is deprecated")
    async def get_users_newest_first(self, limit: int = None, next_pagination: str = None) -> UsersResponse:
        if limit is None:
            limit = 100
        next_pagination_tokens = NextPaginationToken('null', 'null')
        if next_pagination is not None:
            next_pagination_tokens = extract_pagination_token(next_pagination)
        email_password_result_promise = self.ep_get_users_newest_first(limit, next_pagination_tokens.email_password_pagination_token)
        third_party_result = UsersResponse([], None) if self.tp_get_users_newest_first is None else await self.tp_get_users_newest_first(
            limit, next_pagination_tokens.third_party_pagination_token)
        email_password_result = await email_password_result_promise
        return combine_pagination_results(
            third_party_result, email_password_result, limit, True)

    @deprecated(reason='This method is deprecated')
    async def get_user_count(self) -> int:
        emailpassword_count = await self.ep_get_user_count()
        thirdparty_count = await self.tp_get_user_count() if self.tp_get_user_count is not None else 0
        return emailpassword_count + thirdparty_count
