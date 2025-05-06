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

from typing import TYPE_CHECKING, Any, Dict, List, Optional, Union

from typing_extensions import Literal

from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.types import RecipeUserId, User
from supertokens_python.types.base import AccountInfoInput

from .interfaces import (
    CanCreatePrimaryUserAccountInfoAlreadyAssociatedError,
    CanCreatePrimaryUserOkResult,
    CanCreatePrimaryUserRecipeUserIdAlreadyLinkedError,
    CanLinkAccountsAccountInfoAlreadyAssociatedError,
    CanLinkAccountsInputUserNotPrimaryError,
    CanLinkAccountsOkResult,
    CanLinkAccountsRecipeUserIdAlreadyLinkedError,
    CreatePrimaryUserAccountInfoAlreadyAssociatedError,
    CreatePrimaryUserOkResult,
    CreatePrimaryUserRecipeUserIdAlreadyLinkedError,
    GetUsersResult,
    LinkAccountsAccountInfoAlreadyAssociatedError,
    LinkAccountsInputUserNotPrimaryError,
    LinkAccountsOkResult,
    LinkAccountsRecipeUserIdAlreadyLinkedError,
    RecipeInterface,
    UnlinkAccountOkResult,
)
from .types import AccountLinkingConfig, RecipeLevelUser

if TYPE_CHECKING:
    from supertokens_python.querier import Querier

    from .recipe import AccountLinkingRecipe


class RecipeImplementation(RecipeInterface):
    def __init__(
        self,
        querier: Querier,
        recipe_instance: AccountLinkingRecipe,
        config: AccountLinkingConfig,
    ):
        super().__init__()
        self.querier = querier
        self.recipe_instance = recipe_instance
        self.config = config

    async def get_users(
        self,
        tenant_id: str,
        time_joined_order: Literal["ASC", "DESC"],
        limit: Optional[int],
        pagination_token: Optional[str],
        include_recipe_ids: Optional[List[str]],
        query: Optional[Dict[str, str]],
        user_context: Dict[str, Any],
    ) -> GetUsersResult:
        include_recipe_ids_str = None
        if include_recipe_ids is not None:
            include_recipe_ids_str = ",".join(include_recipe_ids)

        params: Dict[str, Any] = {
            "timeJoinedOrder": time_joined_order,
        }
        if limit is not None:
            params["limit"] = limit
        if pagination_token is not None:
            params["paginationToken"] = pagination_token
        if include_recipe_ids_str is not None:
            params["includeRecipeIds"] = include_recipe_ids_str
        if query:
            params.update(query)

        response = await self.querier.send_get_request(
            NormalisedURLPath(f"/{tenant_id or 'public'}/users"), params, user_context
        )

        return GetUsersResult(
            users=[User.from_json(u) for u in response["users"]],
            next_pagination_token=response.get("nextPaginationToken"),
        )

    async def can_create_primary_user(
        self, recipe_user_id: RecipeUserId, user_context: Dict[str, Any]
    ) -> Union[
        CanCreatePrimaryUserOkResult,
        CanCreatePrimaryUserRecipeUserIdAlreadyLinkedError,
        CanCreatePrimaryUserAccountInfoAlreadyAssociatedError,
    ]:
        response = await self.querier.send_get_request(
            NormalisedURLPath("/recipe/accountlinking/user/primary/check"),
            {
                "recipeUserId": recipe_user_id.get_as_string(),
            },
            user_context,
        )

        if response["status"] == "OK":
            return CanCreatePrimaryUserOkResult(response["wasAlreadyAPrimaryUser"])
        elif (
            response["status"]
            == "RECIPE_USER_ID_ALREADY_LINKED_WITH_PRIMARY_USER_ID_ERROR"
        ):
            return CanCreatePrimaryUserRecipeUserIdAlreadyLinkedError(
                response["primaryUserId"], response["description"]
            )
        elif (
            response["status"]
            == "ACCOUNT_INFO_ALREADY_ASSOCIATED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR"
        ):
            return CanCreatePrimaryUserAccountInfoAlreadyAssociatedError(
                response["primaryUserId"], response["description"]
            )
        else:
            raise Exception(f"Unknown response status: {response['status']}")

    async def create_primary_user(
        self, recipe_user_id: RecipeUserId, user_context: Dict[str, Any]
    ) -> Union[
        CreatePrimaryUserOkResult,
        CreatePrimaryUserRecipeUserIdAlreadyLinkedError,
        CreatePrimaryUserAccountInfoAlreadyAssociatedError,
    ]:
        response = await self.querier.send_post_request(
            NormalisedURLPath("/recipe/accountlinking/user/primary"),
            {
                "recipeUserId": recipe_user_id.get_as_string(),
            },
            user_context,
        )

        if response["status"] == "OK":
            return CreatePrimaryUserOkResult(
                User.from_json(response["user"]),
                response["wasAlreadyAPrimaryUser"],
            )
        elif (
            response["status"]
            == "RECIPE_USER_ID_ALREADY_LINKED_WITH_PRIMARY_USER_ID_ERROR"
        ):
            return CreatePrimaryUserRecipeUserIdAlreadyLinkedError(
                response["primaryUserId"], response["description"]
            )
        elif (
            response["status"]
            == "ACCOUNT_INFO_ALREADY_ASSOCIATED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR"
        ):
            return CreatePrimaryUserAccountInfoAlreadyAssociatedError(
                response["primaryUserId"], response["description"]
            )
        else:
            raise Exception(f"Unknown response status: {response['status']}")

    async def can_link_accounts(
        self,
        recipe_user_id: RecipeUserId,
        primary_user_id: str,
        user_context: Dict[str, Any],
    ) -> Union[
        CanLinkAccountsOkResult,
        CanLinkAccountsRecipeUserIdAlreadyLinkedError,
        CanLinkAccountsAccountInfoAlreadyAssociatedError,
        CanLinkAccountsInputUserNotPrimaryError,
    ]:
        response = await self.querier.send_get_request(
            NormalisedURLPath("/recipe/accountlinking/user/link/check"),
            {
                "recipeUserId": recipe_user_id.get_as_string(),
                "primaryUserId": primary_user_id,
            },
            user_context,
        )

        if response["status"] == "OK":
            return CanLinkAccountsOkResult(response["accountsAlreadyLinked"])
        elif (
            response["status"]
            == "RECIPE_USER_ID_ALREADY_LINKED_WITH_PRIMARY_USER_ID_ERROR"
        ):
            return CanLinkAccountsRecipeUserIdAlreadyLinkedError(
                response["primaryUserId"], response["description"]
            )
        elif (
            response["status"]
            == "ACCOUNT_INFO_ALREADY_ASSOCIATED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR"
        ):
            return CanLinkAccountsAccountInfoAlreadyAssociatedError(
                response["primaryUserId"], response["description"]
            )
        elif response["status"] == "INPUT_USER_IS_NOT_A_PRIMARY_USER":
            return CanLinkAccountsInputUserNotPrimaryError(response["description"])
        else:
            raise Exception(f"Unknown response status: {response['status']}")

    async def link_accounts(
        self,
        recipe_user_id: RecipeUserId,
        primary_user_id: str,
        user_context: Dict[str, Any],
    ) -> Union[
        LinkAccountsOkResult,
        LinkAccountsRecipeUserIdAlreadyLinkedError,
        LinkAccountsAccountInfoAlreadyAssociatedError,
        LinkAccountsInputUserNotPrimaryError,
    ]:
        response = await self.querier.send_post_request(
            NormalisedURLPath("/recipe/accountlinking/user/link"),
            {
                "recipeUserId": recipe_user_id.get_as_string(),
                "primaryUserId": primary_user_id,
            },
            user_context,
        )

        if response["status"] in [
            "OK",
            "RECIPE_USER_ID_ALREADY_LINKED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR",
        ]:
            response["user"] = User.from_json(response["user"])

        if response["status"] == "OK":
            user = response["user"]
            if not response["accountsAlreadyLinked"]:
                await self.recipe_instance.verify_email_for_recipe_user_if_linked_accounts_are_verified(
                    user=user,
                    recipe_user_id=recipe_user_id,
                    user_context=user_context,
                )

                updated_user = await self.get_user(
                    user_id=primary_user_id,
                    user_context=user_context,
                )
                if updated_user is None:
                    raise Exception("This error should never be thrown")
                user = updated_user

                login_method_info = next(
                    (
                        lm
                        for lm in user.login_methods
                        if lm.recipe_user_id.get_as_string()
                        == recipe_user_id.get_as_string()
                    ),
                    None,
                )
                if login_method_info is None:
                    raise Exception("This error should never be thrown")

                await self.config.on_account_linked(
                    user,
                    RecipeLevelUser.from_login_method(login_method_info),
                    user_context,
                )

            response["user"] = user

        if response["status"] == "OK":
            return LinkAccountsOkResult(
                user=response["user"],
                accounts_already_linked=response["accountsAlreadyLinked"],
            )
        elif (
            response["status"]
            == "RECIPE_USER_ID_ALREADY_LINKED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR"
        ):
            return LinkAccountsRecipeUserIdAlreadyLinkedError(
                primary_user_id=response["primaryUserId"],
                user=response["user"],
                description=response["description"],
            )
        elif (
            response["status"]
            == "ACCOUNT_INFO_ALREADY_ASSOCIATED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR"
        ):
            return LinkAccountsAccountInfoAlreadyAssociatedError(
                primary_user_id=response["primaryUserId"],
                description=response["description"],
            )
        elif response["status"] == "INPUT_USER_IS_NOT_A_PRIMARY_USER":
            return LinkAccountsInputUserNotPrimaryError()
        else:
            raise Exception(f"Unknown response status: {response['status']}")

    async def unlink_account(
        self, recipe_user_id: RecipeUserId, user_context: Dict[str, Any]
    ) -> UnlinkAccountOkResult:
        response = await self.querier.send_post_request(
            NormalisedURLPath("/recipe/accountlinking/user/unlink"),
            {
                "recipeUserId": recipe_user_id.get_as_string(),
            },
            user_context,
        )
        return UnlinkAccountOkResult(
            response["wasRecipeUserDeleted"], response["wasLinked"]
        )

    async def get_user(
        self, user_id: str, user_context: Dict[str, Any]
    ) -> Optional[User]:
        response = await self.querier.send_get_request(
            NormalisedURLPath("/user/id"),
            {
                "userId": user_id,
            },
            user_context,
        )
        if response["status"] == "OK":
            return User.from_json(response["user"])
        return None

    async def list_users_by_account_info(
        self,
        tenant_id: str,
        account_info: AccountInfoInput,
        do_union_of_account_info: bool,
        user_context: Dict[str, Any],
    ) -> List[User]:
        params: Dict[str, Any] = {
            "doUnionOfAccountInfo": do_union_of_account_info,
        }
        if account_info.email is not None:
            params["email"] = account_info.email
        if account_info.phone_number is not None:
            params["phoneNumber"] = account_info.phone_number

        if account_info.third_party:
            params["thirdPartyId"] = account_info.third_party.id
            params["thirdPartyUserId"] = account_info.third_party.user_id

        if account_info.webauthn:
            params["webauthnCredentialId"] = account_info.webauthn.credential_id

        response = await self.querier.send_get_request(
            NormalisedURLPath(f"/{tenant_id or 'public'}/users/by-accountinfo"),
            params,
            user_context,
        )

        return [User.from_json(u) for u in response["users"]]

    async def delete_user(
        self,
        user_id: str,
        remove_all_linked_accounts: bool,
        user_context: Dict[str, Any],
    ) -> None:
        await self.querier.send_post_request(
            NormalisedURLPath("/user/remove"),
            {
                "userId": user_id,
                "removeAllLinkedAccounts": remove_all_linked_accounts,
            },
            user_context,
        )
