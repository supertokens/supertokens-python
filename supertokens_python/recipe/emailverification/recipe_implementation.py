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

from typing import TYPE_CHECKING, Any, Awaitable, Callable, Dict, Optional, Union

from supertokens_python.asyncio import get_user
from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.types import RecipeUserId, User

from .interfaces import (
    CreateEmailVerificationTokenEmailAlreadyVerifiedError,
    CreateEmailVerificationTokenOkResult,
    EmailDoesNotExistError,
    GetEmailForUserIdOkResult,
    RecipeInterface,
    RevokeEmailVerificationTokensOkResult,
    UnknownUserIdError,
    UnverifyEmailOkResult,
    VerifyEmailUsingTokenInvalidTokenError,
    VerifyEmailUsingTokenOkResult,
)
from .types import EmailVerificationUser

if TYPE_CHECKING:
    from supertokens_python.querier import Querier


class RecipeImplementation(RecipeInterface):
    def __init__(
        self,
        querier: Querier,
        get_email_for_recipe_user_id: Callable[
            [Optional[User], RecipeUserId, Dict[str, Any]],
            Awaitable[
                Union[
                    GetEmailForUserIdOkResult,
                    EmailDoesNotExistError,
                    UnknownUserIdError,
                ]
            ],
        ],
    ):
        super().__init__()
        self.querier = querier
        self.get_email_for_recipe_user_id = get_email_for_recipe_user_id

    async def create_email_verification_token(
        self,
        recipe_user_id: RecipeUserId,
        email: str,
        tenant_id: str,
        user_context: Dict[str, Any],
    ) -> Union[
        CreateEmailVerificationTokenOkResult,
        CreateEmailVerificationTokenEmailAlreadyVerifiedError,
    ]:
        data = {"userId": recipe_user_id.get_as_string(), "email": email}
        response = await self.querier.send_post_request(
            NormalisedURLPath(f"{tenant_id}/recipe/user/email/verify/token"),
            data,
            user_context,
        )
        if "status" in response and response["status"] == "OK":
            return CreateEmailVerificationTokenOkResult(response["token"])
        return CreateEmailVerificationTokenEmailAlreadyVerifiedError()

    async def verify_email_using_token(
        self,
        token: str,
        tenant_id: str,
        attempt_account_linking: bool,
        user_context: Dict[str, Any],
    ) -> Union[VerifyEmailUsingTokenOkResult, VerifyEmailUsingTokenInvalidTokenError]:
        data = {"method": "token", "token": token}
        response = await self.querier.send_post_request(
            NormalisedURLPath(f"{tenant_id}/recipe/user/email/verify"),
            data,
            user_context,
        )
        if response["status"] == "OK":
            recipe_user_id = RecipeUserId(response["userId"])
            if attempt_account_linking:
                updated_user = await get_user(
                    recipe_user_id.get_as_string(), user_context
                )

                if updated_user:
                    # Check if the verified email is currently associated with the user ID
                    email_info = await self.get_email_for_recipe_user_id(
                        updated_user, recipe_user_id, user_context
                    )
                    if (
                        isinstance(email_info, GetEmailForUserIdOkResult)
                        and email_info.email == response["email"]
                    ):
                        from ..accountlinking.recipe import AccountLinkingRecipe

                        account_linking = AccountLinkingRecipe.get_instance()
                        await account_linking.try_linking_by_account_info_or_create_primary_user(
                            tenant_id=tenant_id,
                            input_user=updated_user,
                            session=None,
                            user_context=user_context,
                        )

            return VerifyEmailUsingTokenOkResult(
                EmailVerificationUser(recipe_user_id, response["email"])
            )
        else:
            return VerifyEmailUsingTokenInvalidTokenError()

    async def is_email_verified(
        self, recipe_user_id: RecipeUserId, email: str, user_context: Dict[str, Any]
    ) -> bool:
        params = {"userId": recipe_user_id.get_as_string(), "email": email}
        response = await self.querier.send_get_request(
            NormalisedURLPath("/recipe/user/email/verify"), params, user_context
        )
        return response["isVerified"]

    async def revoke_email_verification_tokens(
        self,
        recipe_user_id: RecipeUserId,
        email: str,
        tenant_id: str,
        user_context: Dict[str, Any],
    ) -> RevokeEmailVerificationTokensOkResult:
        data = {"userId": recipe_user_id.get_as_string(), "email": email}
        await self.querier.send_post_request(
            NormalisedURLPath(f"{tenant_id}/recipe/user/email/verify/token/remove"),
            data,
            user_context,
        )
        return RevokeEmailVerificationTokensOkResult()

    async def unverify_email(
        self, recipe_user_id: RecipeUserId, email: str, user_context: Dict[str, Any]
    ) -> UnverifyEmailOkResult:
        data = {"userId": recipe_user_id.get_as_string(), "email": email}
        await self.querier.send_post_request(
            NormalisedURLPath("/recipe/user/email/verify/remove"), data, user_context
        )
        return UnverifyEmailOkResult()
