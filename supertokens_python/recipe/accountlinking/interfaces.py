# Copyright (c) 2024, VRAI Labs and/or its affiliates. All rights reserved.
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

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Union

from typing_extensions import Literal

from supertokens_python.types.base import AccountInfoInput

if TYPE_CHECKING:
    from supertokens_python.types import (
        RecipeUserId,
        User,
    )


class RecipeInterface(ABC):
    @abstractmethod
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
        pass

    @abstractmethod
    async def can_create_primary_user(
        self, recipe_user_id: RecipeUserId, user_context: Dict[str, Any]
    ) -> Union[
        CanCreatePrimaryUserOkResult,
        CanCreatePrimaryUserRecipeUserIdAlreadyLinkedError,
        CanCreatePrimaryUserAccountInfoAlreadyAssociatedError,
    ]:
        pass

    @abstractmethod
    async def create_primary_user(
        self, recipe_user_id: RecipeUserId, user_context: Dict[str, Any]
    ) -> Union[
        CreatePrimaryUserOkResult,
        CreatePrimaryUserRecipeUserIdAlreadyLinkedError,
        CreatePrimaryUserAccountInfoAlreadyAssociatedError,
    ]:
        pass

    @abstractmethod
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
        pass

    @abstractmethod
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
        pass

    @abstractmethod
    async def unlink_account(
        self, recipe_user_id: RecipeUserId, user_context: Dict[str, Any]
    ) -> UnlinkAccountOkResult:
        pass

    @abstractmethod
    async def get_user(
        self, user_id: str, user_context: Dict[str, Any]
    ) -> Optional[User]:
        pass

    @abstractmethod
    async def list_users_by_account_info(
        self,
        tenant_id: str,
        account_info: AccountInfoInput,
        do_union_of_account_info: bool,
        user_context: Dict[str, Any],
    ) -> List[User]:
        pass

    @abstractmethod
    async def delete_user(
        self,
        user_id: str,
        remove_all_linked_accounts: bool,
        user_context: Dict[str, Any],
    ) -> None:
        pass


class GetUsersResult:
    def __init__(self, users: List[User], next_pagination_token: Optional[str]):
        self.users = users
        self.next_pagination_token = next_pagination_token


class CanCreatePrimaryUserOkResult:
    def __init__(self, was_already_a_primary_user: bool):
        self.status: Literal["OK"] = "OK"
        self.was_already_a_primary_user = was_already_a_primary_user


class CanCreatePrimaryUserRecipeUserIdAlreadyLinkedError:
    def __init__(self, primary_user_id: str, description: str):
        self.status: Literal[
            "RECIPE_USER_ID_ALREADY_LINKED_WITH_PRIMARY_USER_ID_ERROR"
        ] = "RECIPE_USER_ID_ALREADY_LINKED_WITH_PRIMARY_USER_ID_ERROR"
        self.primary_user_id = primary_user_id
        self.description = description


class CanCreatePrimaryUserAccountInfoAlreadyAssociatedError:
    def __init__(self, primary_user_id: str, description: str):
        self.status: Literal[
            "ACCOUNT_INFO_ALREADY_ASSOCIATED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR"
        ] = "ACCOUNT_INFO_ALREADY_ASSOCIATED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR"
        self.primary_user_id = primary_user_id
        self.description = description


class CreatePrimaryUserOkResult:
    def __init__(self, user: User, was_already_a_primary_user: bool):
        self.status: Literal["OK"] = "OK"
        self.user = user
        self.was_already_a_primary_user = was_already_a_primary_user

    def to_json(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "user": self.user.to_json(),
            "wasAlreadyAPrimaryUser": self.was_already_a_primary_user,
        }


class CreatePrimaryUserRecipeUserIdAlreadyLinkedError:
    def __init__(self, primary_user_id: str, description: Optional[str] = None):
        self.status: Literal[
            "RECIPE_USER_ID_ALREADY_LINKED_WITH_PRIMARY_USER_ID_ERROR"
        ] = "RECIPE_USER_ID_ALREADY_LINKED_WITH_PRIMARY_USER_ID_ERROR"
        self.primary_user_id = primary_user_id
        self.description = description


class CreatePrimaryUserAccountInfoAlreadyAssociatedError:
    def __init__(self, primary_user_id: str, description: Optional[str] = None):
        self.status: Literal[
            "ACCOUNT_INFO_ALREADY_ASSOCIATED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR"
        ] = "ACCOUNT_INFO_ALREADY_ASSOCIATED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR"
        self.primary_user_id = primary_user_id
        self.description = description


class CanLinkAccountsOkResult:
    def __init__(self, accounts_already_linked: bool):
        self.status: Literal["OK"] = "OK"
        self.accounts_already_linked = accounts_already_linked


class CanLinkAccountsRecipeUserIdAlreadyLinkedError:
    def __init__(
        self, primary_user_id: Optional[str] = None, description: Optional[str] = None
    ):
        self.status: Literal[
            "RECIPE_USER_ID_ALREADY_LINKED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR"
        ] = "RECIPE_USER_ID_ALREADY_LINKED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR"
        self.primary_user_id = primary_user_id
        self.description = description


class CanLinkAccountsAccountInfoAlreadyAssociatedError:
    def __init__(
        self, primary_user_id: Optional[str] = None, description: Optional[str] = None
    ):
        self.status: Literal[
            "ACCOUNT_INFO_ALREADY_ASSOCIATED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR"
        ] = "ACCOUNT_INFO_ALREADY_ASSOCIATED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR"
        self.primary_user_id = primary_user_id
        self.description = description


class CanLinkAccountsInputUserNotPrimaryError:
    def __init__(self, description: Optional[str] = None):
        self.status: Literal["INPUT_USER_IS_NOT_A_PRIMARY_USER"] = (
            "INPUT_USER_IS_NOT_A_PRIMARY_USER"
        )
        self.description = description


class LinkAccountsOkResult:
    def __init__(self, accounts_already_linked: bool, user: User):
        self.status: Literal["OK"] = "OK"
        self.accounts_already_linked = accounts_already_linked
        self.user = user

    def to_json(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "accountsAlreadyLinked": self.accounts_already_linked,
            "user": self.user.to_json(),
        }


class LinkAccountsRecipeUserIdAlreadyLinkedError:
    def __init__(
        self,
        primary_user_id: str,
        user: User,
        description: str,
    ):
        self.status: Literal[
            "RECIPE_USER_ID_ALREADY_LINKED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR"
        ] = "RECIPE_USER_ID_ALREADY_LINKED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR"
        self.primary_user_id = primary_user_id
        self.user = user
        self.description = description


class LinkAccountsAccountInfoAlreadyAssociatedError:
    def __init__(
        self,
        primary_user_id: Optional[str] = None,
        description: Optional[str] = None,
    ):
        self.status: Literal[
            "ACCOUNT_INFO_ALREADY_ASSOCIATED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR"
        ] = "ACCOUNT_INFO_ALREADY_ASSOCIATED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR"
        self.primary_user_id = primary_user_id
        self.description = description


class LinkAccountsInputUserNotPrimaryError:
    def __init__(self):
        self.status: Literal["INPUT_USER_IS_NOT_A_PRIMARY_USER"] = (
            "INPUT_USER_IS_NOT_A_PRIMARY_USER"
        )


class UnlinkAccountOkResult:
    def __init__(self, was_recipe_user_deleted: bool, was_linked: bool):
        self.status: Literal["OK"] = "OK"
        self.was_recipe_user_deleted = was_recipe_user_deleted
        self.was_linked = was_linked
