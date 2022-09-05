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

from typing import TYPE_CHECKING, Any, Dict, List, Union

import supertokens_python.recipe.emailpassword.interfaces as EPInterfaces

if TYPE_CHECKING:
    from supertokens_python.querier import Querier

from supertokens_python.recipe.emailpassword.recipe_implementation import (
    RecipeImplementation as EmailPasswordImplementation,
)
from supertokens_python.recipe.thirdparty.recipe_implementation import (
    RecipeImplementation as ThirdPartyImplementation,
)

from ..interfaces import (
    CreateResetPasswordOkResult,
    CreateResetPasswordWrongUserIdError,
    EmailPasswordSignInOkResult,
    EmailPasswordSignInWrongCredentialsError,
    EmailPasswordSignUpEmailAlreadyExistsError,
    EmailPasswordSignUpOkResult,
    RecipeInterface,
    ResetPasswordUsingTokenInvalidTokenError,
    ResetPasswordUsingTokenOkResult,
    ThirdPartySignInUpOkResult,
    UpdateEmailOrPasswordEmailAlreadyExistsError,
    UpdateEmailOrPasswordOkResult,
    UpdateEmailOrPasswordUnknownUserIdError,
)
from ..types import User
from .email_password_recipe_implementation import (
    RecipeImplementation as DerivedEmailPasswordImplementation,
)
from .third_party_recipe_implementation import (
    RecipeImplementation as DerivedThirdPartyImplementation,
)


class RecipeImplementation(RecipeInterface):
    def __init__(
        self, emailpassword_querier: Querier, thirdparty_querier: Union[Querier, None]
    ):
        super().__init__()
        emailpassword_implementation = EmailPasswordImplementation(
            emailpassword_querier
        )

        self.ep_get_user_by_id = emailpassword_implementation.get_user_by_id
        self.ep_get_user_by_email = emailpassword_implementation.get_user_by_email
        self.ep_create_reset_password_token = (
            emailpassword_implementation.create_reset_password_token
        )
        self.ep_reset_password_using_token = (
            emailpassword_implementation.reset_password_using_token
        )
        self.ep_sign_in = emailpassword_implementation.sign_in
        self.ep_sign_up = emailpassword_implementation.sign_up
        self.ep_update_email_or_password = (
            emailpassword_implementation.update_email_or_password
        )

        derived_ep = DerivedEmailPasswordImplementation(self)
        emailpassword_implementation.create_reset_password_token = (
            derived_ep.create_reset_password_token
        )
        emailpassword_implementation.get_user_by_email = derived_ep.get_user_by_email
        emailpassword_implementation.get_user_by_id = derived_ep.get_user_by_id
        emailpassword_implementation.reset_password_using_token = (
            derived_ep.reset_password_using_token
        )
        emailpassword_implementation.sign_in = derived_ep.sign_in
        emailpassword_implementation.sign_up = derived_ep.sign_up
        emailpassword_implementation.update_email_or_password = (
            derived_ep.update_email_or_password
        )

        self.tp_get_user_by_id = None
        self.tp_get_users_by_email = None
        self.tp_get_user_by_thirdparty_info = None
        self.tp_sign_in_up = None
        if thirdparty_querier is not None:
            thirdparty_implementation = ThirdPartyImplementation(thirdparty_querier)
            self.tp_get_user_by_id = thirdparty_implementation.get_user_by_id
            self.tp_get_users_by_email = thirdparty_implementation.get_users_by_email
            self.tp_get_user_by_thirdparty_info = (
                thirdparty_implementation.get_user_by_thirdparty_info
            )
            self.tp_sign_in_up = thirdparty_implementation.sign_in_up

            derived_tp = DerivedThirdPartyImplementation(self)
            thirdparty_implementation.get_user_by_id = derived_tp.get_user_by_id
            thirdparty_implementation.get_users_by_email = derived_tp.get_users_by_email
            thirdparty_implementation.get_user_by_thirdparty_info = (
                derived_tp.get_user_by_thirdparty_info
            )
            thirdparty_implementation.sign_in_up = derived_tp.sign_in_up

    async def get_user_by_id(
        self, user_id: str, user_context: Dict[str, Any]
    ) -> Union[User, None]:
        ep_user = await self.ep_get_user_by_id(user_id, user_context)

        if ep_user is not None:
            return User(
                user_id=ep_user.user_id,
                email=ep_user.email,
                time_joined=ep_user.time_joined,
                third_party_info=None,
            )

        if self.tp_get_user_by_id is None:
            return None

        tp_user = await self.tp_get_user_by_id(user_id, user_context)
        if tp_user is None:
            return None
        return User(
            user_id=tp_user.user_id,
            email=tp_user.email,
            time_joined=tp_user.time_joined,
            third_party_info=tp_user.third_party_info,
        )

    async def get_users_by_email(
        self, email: str, user_context: Dict[str, Any]
    ) -> List[User]:
        result: List[User] = []
        ep_user = await self.ep_get_user_by_email(email, user_context)

        if ep_user is not None:
            result.append(
                User(
                    user_id=ep_user.user_id,
                    email=ep_user.email,
                    time_joined=ep_user.time_joined,
                    third_party_info=None,
                )
            )

        if self.tp_get_users_by_email is None:
            return result

        tp_users = await self.tp_get_users_by_email(email, user_context)

        for tp_user in tp_users:
            result.append(
                User(
                    user_id=tp_user.user_id,
                    email=tp_user.email,
                    time_joined=tp_user.time_joined,
                    third_party_info=tp_user.third_party_info,
                )
            )

        return result

    async def get_user_by_thirdparty_info(
        self,
        third_party_id: str,
        third_party_user_id: str,
        user_context: Dict[str, Any],
    ) -> Union[User, None]:
        if self.tp_get_user_by_thirdparty_info is None:
            return None
        tp_user = await self.tp_get_user_by_thirdparty_info(
            third_party_id, third_party_user_id, user_context
        )

        if tp_user is None:
            return None

        return User(
            user_id=tp_user.user_id,
            email=tp_user.email,
            time_joined=tp_user.time_joined,
            third_party_info=tp_user.third_party_info,
        )

    async def thirdparty_sign_in_up(
        self,
        third_party_id: str,
        third_party_user_id: str,
        email: str,
        user_context: Dict[str, Any],
    ) -> ThirdPartySignInUpOkResult:
        if self.tp_sign_in_up is None:
            raise Exception("No thirdparty provider configured")
        result = await self.tp_sign_in_up(
            third_party_id, third_party_user_id, email, user_context
        )
        return ThirdPartySignInUpOkResult(
            User(
                result.user.user_id,
                result.user.email,
                result.user.time_joined,
                result.user.third_party_info,
            ),
            result.created_new_user,
        )

    async def emailpassword_sign_in(
        self, email: str, password: str, user_context: Dict[str, Any]
    ) -> Union[EmailPasswordSignInOkResult, EmailPasswordSignInWrongCredentialsError]:
        result = await self.ep_sign_in(email, password, user_context)
        if isinstance(result, EPInterfaces.SignInOkResult):
            return EmailPasswordSignInOkResult(
                User(
                    result.user.user_id,
                    result.user.email,
                    result.user.time_joined,
                    None,
                )
            )
        return result

    async def emailpassword_sign_up(
        self, email: str, password: str, user_context: Dict[str, Any]
    ) -> Union[EmailPasswordSignUpOkResult, EmailPasswordSignUpEmailAlreadyExistsError]:
        result = await self.ep_sign_up(email, password, user_context)
        if isinstance(result, EPInterfaces.SignUpOkResult):
            return EmailPasswordSignUpOkResult(
                User(
                    result.user.user_id,
                    result.user.email,
                    result.user.time_joined,
                    None,
                )
            )
        return result

    async def create_reset_password_token(
        self, user_id: str, user_context: Dict[str, Any]
    ) -> Union[CreateResetPasswordOkResult, CreateResetPasswordWrongUserIdError]:
        return await self.ep_create_reset_password_token(user_id, user_context)

    async def reset_password_using_token(
        self, token: str, new_password: str, user_context: Dict[str, Any]
    ) -> Union[
        ResetPasswordUsingTokenOkResult, ResetPasswordUsingTokenInvalidTokenError
    ]:
        return await self.ep_reset_password_using_token(
            token, new_password, user_context
        )

    async def update_email_or_password(
        self,
        user_id: str,
        email: Union[None, str],
        password: Union[None, str],
        user_context: Dict[str, Any],
    ) -> Union[
        UpdateEmailOrPasswordOkResult,
        UpdateEmailOrPasswordEmailAlreadyExistsError,
        UpdateEmailOrPasswordUnknownUserIdError,
    ]:
        user = await self.get_user_by_id(user_id, user_context)
        if user is None:
            return UpdateEmailOrPasswordUnknownUserIdError()
        if user.third_party_info is not None:
            raise Exception(
                "Cannot update email or password of a user who signed up using third party login."
            )
        return await self.ep_update_email_or_password(
            user_id, email, password, user_context
        )
