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

from typing import Any, Dict, Union

from supertokens_python.recipe.emailpassword.interfaces import (
    CreateResetPasswordOkResult,
    CreateResetPasswordWrongUserIdError,
    RecipeInterface,
    ResetPasswordUsingTokenOkResult,
    ResetPasswordUsingTokenInvalidTokenError,
    SignInOkResult,
    SignInWrongCredentialsError,
    SignUpEmailAlreadyExistsError,
    SignUpOkResult,
    UpdateEmailOrPasswordEmailAlreadyExistsError,
    UpdateEmailOrPasswordOkResult,
    UpdateEmailOrPasswordUnknownUserIdError,
    UpdateEmailOrPasswordPasswordPolicyViolationError,
)
from supertokens_python.recipe.emailpassword.types import User

from ..interfaces import (
    RecipeInterface as ThirdPartyEmailPasswordRecipeInterface,
    EmailPasswordSignInOkResult,
    EmailPasswordSignUpOkResult,
)


class RecipeImplementation(RecipeInterface):
    def __init__(
        self,
        recipe_implementation: ThirdPartyEmailPasswordRecipeInterface,
    ):
        super().__init__()
        self.recipe_implementation = recipe_implementation

    async def get_user_by_id(
        self, user_id: str, user_context: Dict[str, Any]
    ) -> Union[User, None]:
        user = await self.recipe_implementation.get_user_by_id(user_id, user_context)

        if user is None or user.third_party_info is not None:
            return None

        return User(
            user_id=user.user_id,
            email=user.email,
            time_joined=user.time_joined,
            tenant_ids=user.tenant_ids,
        )

    async def get_user_by_email(
        self, email: str, tenant_id: str, user_context: Dict[str, Any]
    ) -> Union[User, None]:
        users = await self.recipe_implementation.get_users_by_email(
            email, tenant_id, user_context
        )

        for user in users:
            if user.third_party_info is None:
                return User(
                    user_id=user.user_id,
                    email=user.email,
                    time_joined=user.time_joined,
                    tenant_ids=user.tenant_ids,
                )

        return None

    async def create_reset_password_token(
        self, user_id: str, tenant_id: str, user_context: Dict[str, Any]
    ) -> Union[CreateResetPasswordOkResult, CreateResetPasswordWrongUserIdError]:
        return await self.recipe_implementation.create_reset_password_token(
            user_id, tenant_id, user_context
        )

    async def reset_password_using_token(
        self,
        token: str,
        new_password: str,
        tenant_id: str,
        user_context: Dict[str, Any],
    ) -> Union[
        ResetPasswordUsingTokenOkResult, ResetPasswordUsingTokenInvalidTokenError
    ]:
        return await self.recipe_implementation.reset_password_using_token(
            token, new_password, tenant_id, user_context
        )

    async def sign_in(
        self, email: str, password: str, tenant_id: str, user_context: Dict[str, Any]
    ) -> Union[SignInOkResult, SignInWrongCredentialsError]:
        result = await self.recipe_implementation.emailpassword_sign_in(
            email, password, tenant_id, user_context
        )
        if isinstance(result, EmailPasswordSignInOkResult):
            return SignInOkResult(
                User(
                    result.user.user_id,
                    result.user.email,
                    result.user.time_joined,
                    result.user.tenant_ids,
                )
            )
        return result

    async def sign_up(
        self, email: str, password: str, tenant_id: str, user_context: Dict[str, Any]
    ) -> Union[SignUpOkResult, SignUpEmailAlreadyExistsError]:
        result = await self.recipe_implementation.emailpassword_sign_up(
            email, password, tenant_id, user_context
        )
        if isinstance(result, EmailPasswordSignUpOkResult):
            return SignUpOkResult(
                User(
                    result.user.user_id,
                    result.user.email,
                    result.user.time_joined,
                    result.user.tenant_ids,
                )
            )
        return result

    async def update_email_or_password(
        self,
        user_id: str,
        email: Union[str, None],
        password: Union[str, None],
        apply_password_policy: Union[bool, None],
        tenant_id_for_password_policy: str,
        user_context: Dict[str, Any],
    ) -> Union[
        UpdateEmailOrPasswordOkResult,
        UpdateEmailOrPasswordEmailAlreadyExistsError,
        UpdateEmailOrPasswordUnknownUserIdError,
        UpdateEmailOrPasswordPasswordPolicyViolationError,
    ]:
        return await self.recipe_implementation.update_email_or_password(
            user_id,
            email,
            password,
            apply_password_policy,
            tenant_id_for_password_policy,
            user_context,
        )
