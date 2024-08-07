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

from typing import TYPE_CHECKING, Any, Dict, Union, List, Optional
from typing_extensions import Literal


from .interfaces import (
    RecipeInterface,
    GetUsersResult,
    CanCreatePrimaryUserOkResult,
    CanCreatePrimaryUserRecipeUserIdAlreadyLinkedError,
    CanCreatePrimaryUserAccountInfoAlreadyAssociatedError,
    CreatePrimaryUserOkResult,
    CreatePrimaryUserRecipeUserIdAlreadyLinkedError,
    CreatePrimaryUserAccountInfoAlreadyAssociatedError,
    CanLinkAccountsOkResult,
    CanLinkAccountsRecipeUserIdAlreadyLinkedError,
    CanLinkAccountsAccountInfoAlreadyAssociatedError,
    CanLinkAccountsInputUserNotPrimaryError,
    LinkAccountsOkResult,
    LinkAccountsRecipeUserIdAlreadyLinkedError,
    LinkAccountsAccountInfoAlreadyAssociatedError,
    LinkAccountsInputUserNotPrimaryError,
    UnlinkAccountOkResult,
    AccountLinkingUser,
    RecipeUserId,
    AccountInfo,
)

if TYPE_CHECKING:
    from supertokens_python.querier import Querier


class RecipeImplementation(RecipeInterface):
    def __init__(
        self,
        querier: Querier,
    ):
        super().__init__()
        self.querier = querier

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
        # Implementation for get_users
        raise NotImplementedError("get_users")

    async def can_create_primary_user(
        self, recipe_user_id: RecipeUserId, user_context: Dict[str, Any]
    ) -> Union[
        CanCreatePrimaryUserOkResult,
        CanCreatePrimaryUserRecipeUserIdAlreadyLinkedError,
        CanCreatePrimaryUserAccountInfoAlreadyAssociatedError,
    ]:
        # Implementation for can_create_primary_user
        raise NotImplementedError("can_create_primary_user")

    async def create_primary_user(
        self, recipe_user_id: RecipeUserId, user_context: Dict[str, Any]
    ) -> Union[
        CreatePrimaryUserOkResult,
        CreatePrimaryUserRecipeUserIdAlreadyLinkedError,
        CreatePrimaryUserAccountInfoAlreadyAssociatedError,
    ]:
        # Implementation for create_primary_user
        raise NotImplementedError("create_primary_user")

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
        # Implementation for can_link_accounts
        raise NotImplementedError("can_link_accounts")

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
        # Implementation for link_accounts
        raise NotImplementedError("link_accounts")

    async def unlink_account(
        self, recipe_user_id: RecipeUserId, user_context: Dict[str, Any]
    ) -> UnlinkAccountOkResult:
        # Implementation for unlink_account
        raise NotImplementedError("unlink_account")

    async def get_user(
        self, user_id: str, user_context: Dict[str, Any]
    ) -> Optional[AccountLinkingUser]:
        # Implementation for get_user
        raise NotImplementedError("get_user")

    async def list_users_by_account_info(
        self,
        tenant_id: str,
        account_info: AccountInfo,
        do_union_of_account_info: bool,
        user_context: Dict[str, Any],
    ) -> List[AccountLinkingUser]:
        # Implementation for list_users_by_account_info
        raise NotImplementedError("list_users_by_account_info")

    async def delete_user(
        self,
        user_id: str,
        remove_all_linked_accounts: bool,
        user_context: Dict[str, Any],
    ) -> None:
        # Implementation for delete_user
        raise NotImplementedError("delete_user")
