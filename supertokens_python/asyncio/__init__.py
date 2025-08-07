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
from typing import Any, Dict, List, Optional, Union

from supertokens_python import Supertokens
from supertokens_python.exceptions import BadInputError
from supertokens_python.interfaces import (
    CreateUserIdMappingOkResult,
    DeleteUserIdMappingOkResult,
    GetUserIdMappingOkResult,
    UnknownMappingError,
    UnknownSupertokensUserIDError,
    UpdateOrDeleteUserIdMappingInfoOkResult,
    UserIdMappingAlreadyExistsError,
    UserIDTypes,
)
from supertokens_python.recipe.accountlinking.interfaces import GetUsersResult
from supertokens_python.recipe.accountlinking.recipe import AccountLinkingRecipe
from supertokens_python.recipe.session.interfaces import SessionContainer
from supertokens_python.types import User
from supertokens_python.types.base import AccountInfoInput, UserContext


async def get_users_oldest_first(
    tenant_id: str,
    limit: Union[int, None] = None,
    pagination_token: Union[str, None] = None,
    include_recipe_ids: Union[None, List[str]] = None,
    query: Union[None, Dict[str, str]] = None,
    user_context: Optional[Dict[str, Any]] = None,
) -> GetUsersResult:
    if user_context is None:
        user_context = {}
    return await AccountLinkingRecipe.get_instance().recipe_implementation.get_users(
        tenant_id,
        time_joined_order="ASC",
        limit=limit,
        pagination_token=pagination_token,
        include_recipe_ids=include_recipe_ids,
        query=query,
        user_context=user_context,
    )


async def get_users_newest_first(
    tenant_id: str,
    limit: Union[int, None] = None,
    pagination_token: Union[str, None] = None,
    include_recipe_ids: Union[None, List[str]] = None,
    query: Union[None, Dict[str, str]] = None,
    user_context: Optional[Dict[str, Any]] = None,
) -> GetUsersResult:
    if user_context is None:
        user_context = {}
    return await AccountLinkingRecipe.get_instance().recipe_implementation.get_users(
        tenant_id,
        time_joined_order="DESC",
        limit=limit,
        pagination_token=pagination_token,
        include_recipe_ids=include_recipe_ids,
        query=query,
        user_context=user_context,
    )


async def get_user_count(
    include_recipe_ids: Union[None, List[str]] = None,
    tenant_id: Optional[str] = None,
    user_context: Optional[Dict[str, Any]] = None,
) -> int:
    return await Supertokens.get_instance().get_user_count(
        include_recipe_ids, tenant_id, user_context
    )


async def delete_user(
    user_id: str,
    remove_all_linked_accounts: bool = True,
    user_context: Optional[Dict[str, Any]] = None,
) -> None:
    if user_context is None:
        user_context = {}
    return await AccountLinkingRecipe.get_instance().recipe_implementation.delete_user(
        user_id,
        remove_all_linked_accounts=remove_all_linked_accounts,
        user_context=user_context,
    )


async def get_user(
    user_id: str, user_context: Optional[Dict[str, Any]] = None
) -> Optional[User]:
    if user_context is None:
        user_context = {}
    return await AccountLinkingRecipe.get_instance().recipe_implementation.get_user(
        user_id=user_id, user_context=user_context
    )


async def create_user_id_mapping(
    supertokens_user_id: str,
    external_user_id: str,
    external_user_id_info: Optional[str] = None,
    force: Optional[bool] = None,
    user_context: Optional[Dict[str, Any]] = None,
) -> Union[
    CreateUserIdMappingOkResult,
    UnknownSupertokensUserIDError,
    UserIdMappingAlreadyExistsError,
]:
    return await Supertokens.get_instance().create_user_id_mapping(
        supertokens_user_id,
        external_user_id,
        external_user_id_info,
        force,
        user_context,
    )


async def get_user_id_mapping(
    user_id: str,
    user_id_type: Optional[UserIDTypes] = None,
    user_context: Optional[Dict[str, Any]] = None,
) -> Union[GetUserIdMappingOkResult, UnknownMappingError]:
    return await Supertokens.get_instance().get_user_id_mapping(
        user_id, user_id_type, user_context
    )


async def delete_user_id_mapping(
    user_id: str,
    user_id_type: Optional[UserIDTypes] = None,
    force: Optional[bool] = None,
    user_context: Optional[Dict[str, Any]] = None,
) -> DeleteUserIdMappingOkResult:
    return await Supertokens.get_instance().delete_user_id_mapping(
        user_id, user_id_type, force, user_context
    )


async def update_or_delete_user_id_mapping_info(
    user_id: str,
    user_id_type: Optional[UserIDTypes] = None,
    external_user_id_info: Optional[str] = None,
    user_context: Optional[Dict[str, Any]] = None,
) -> Union[UpdateOrDeleteUserIdMappingInfoOkResult, UnknownMappingError]:
    return await Supertokens.get_instance().update_or_delete_user_id_mapping_info(
        user_id, user_id_type, external_user_id_info, user_context
    )


async def list_users_by_account_info(
    tenant_id: str,
    account_info: AccountInfoInput,
    do_union_of_account_info: bool = False,
    user_context: Optional[Dict[str, Any]] = None,
) -> List[User]:
    if user_context is None:
        user_context = {}
    return await AccountLinkingRecipe.get_instance().recipe_implementation.list_users_by_account_info(
        tenant_id,
        account_info,
        do_union_of_account_info,
        user_context,
    )


# Async not really required, but keeping for consistency
async def is_recipe_initialized(recipe_id: str) -> bool:
    """
    Check if a recipe is initialized.
    :param recipe_id: The ID of the recipe to check.
    :return: Whether the recipe is initialized.
    """
    return any(
        recipe.get_recipe_id() == recipe_id
        for recipe in Supertokens.get_instance().recipe_modules
    )


async def get_available_first_factors(
    tenant_id: str,
    session: Optional[SessionContainer],
    user_context: Optional[UserContext],
):
    from supertokens_python.auth_utils import (
        filter_out_invalid_first_factors_or_throw_if_all_are_invalid,
    )
    from supertokens_python.recipe.multifactorauth.types import FactorIds

    available_first_factors: List[str] = []

    try:
        available_first_factors = (
            await filter_out_invalid_first_factors_or_throw_if_all_are_invalid(
                factor_ids=FactorIds.get_all_factors(),
                tenant_id=tenant_id,
                has_session=session is not None,
                user_context=user_context if user_context is not None else {},
            )
        )
    except BadInputError:
        # All the factors were invalid, so we let it pass through and return the empty list
        pass

    return available_first_factors
