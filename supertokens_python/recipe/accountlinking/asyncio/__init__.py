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
from typing import Any, Dict, Optional

from supertokens_python.asyncio import get_user
from supertokens_python.recipe.session import SessionContainer
from supertokens_python.types import RecipeUserId, User

from ..recipe import AccountLinkingRecipe
from ..types import AccountInfoWithRecipeId


async def create_primary_user_id_or_link_accounts(
    tenant_id: str,
    recipe_user_id: RecipeUserId,
    session: Optional[SessionContainer] = None,
    user_context: Optional[Dict[str, Any]] = None,
) -> User:
    if user_context is None:
        user_context = {}
    user = await get_user(recipe_user_id.get_as_string(), user_context)
    if user is None:
        raise Exception("Unknown recipeUserId")
    link_res = await AccountLinkingRecipe.get_instance().try_linking_by_account_info_or_create_primary_user(
        input_user=user,
        tenant_id=tenant_id,
        session=session,
        user_context=user_context,
    )
    if link_res.status == "NO_LINK":
        return user
    assert link_res.user is not None
    return link_res.user


async def get_primary_user_that_can_be_linked_to_recipe_user_id(
    tenant_id: str,
    recipe_user_id: RecipeUserId,
    user_context: Optional[Dict[str, Any]] = None,
) -> Optional[User]:
    if user_context is None:
        user_context = {}
    user = await get_user(recipe_user_id.get_as_string(), user_context)
    if user is None:
        raise Exception("Unknown recipeUserId")
    return await AccountLinkingRecipe.get_instance().get_primary_user_that_can_be_linked_to_recipe_user_id(
        tenant_id=tenant_id,
        user=user,
        user_context=user_context,
    )


async def can_create_primary_user(
    recipe_user_id: RecipeUserId, user_context: Optional[Dict[str, Any]] = None
):
    if user_context is None:
        user_context = {}
    return await AccountLinkingRecipe.get_instance().recipe_implementation.can_create_primary_user(
        recipe_user_id=recipe_user_id,
        user_context=user_context,
    )


async def create_primary_user(
    recipe_user_id: RecipeUserId, user_context: Optional[Dict[str, Any]] = None
):
    if user_context is None:
        user_context = {}
    return await AccountLinkingRecipe.get_instance().recipe_implementation.create_primary_user(
        recipe_user_id=recipe_user_id,
        user_context=user_context,
    )


async def can_link_accounts(
    recipe_user_id: RecipeUserId,
    primary_user_id: str,
    user_context: Optional[Dict[str, Any]] = None,
):
    if user_context is None:
        user_context = {}
    return await AccountLinkingRecipe.get_instance().recipe_implementation.can_link_accounts(
        recipe_user_id=recipe_user_id,
        primary_user_id=primary_user_id,
        user_context=user_context,
    )


async def link_accounts(
    recipe_user_id: RecipeUserId,
    primary_user_id: str,
    user_context: Optional[Dict[str, Any]] = None,
):
    if user_context is None:
        user_context = {}
    return (
        await AccountLinkingRecipe.get_instance().recipe_implementation.link_accounts(
            recipe_user_id=recipe_user_id,
            primary_user_id=primary_user_id,
            user_context=user_context,
        )
    )


async def unlink_account(
    recipe_user_id: RecipeUserId, user_context: Optional[Dict[str, Any]] = None
):
    if user_context is None:
        user_context = {}
    return (
        await AccountLinkingRecipe.get_instance().recipe_implementation.unlink_account(
            recipe_user_id=recipe_user_id,
            user_context=user_context,
        )
    )


async def is_sign_up_allowed(
    tenant_id: str,
    new_user: AccountInfoWithRecipeId,
    is_verified: bool,
    session: Optional[SessionContainer] = None,
    user_context: Optional[Dict[str, Any]] = None,
):
    if user_context is None:
        user_context = {}
    return await AccountLinkingRecipe.get_instance().is_sign_up_allowed(
        new_user=new_user,
        is_verified=is_verified,
        session=session,
        tenant_id=tenant_id,
        user_context=user_context,
    )


async def is_sign_in_allowed(
    tenant_id: str,
    recipe_user_id: RecipeUserId,
    session: Optional[SessionContainer] = None,
    user_context: Optional[Dict[str, Any]] = None,
):
    if user_context is None:
        user_context = {}
    user = await get_user(recipe_user_id.get_as_string(), user_context)
    if user is None:
        raise Exception("Unknown recipeUserId")

    return await AccountLinkingRecipe.get_instance().is_sign_in_allowed(
        user=user,
        account_info=next(
            lm
            for lm in user.login_methods
            if lm.recipe_user_id.get_as_string() == recipe_user_id.get_as_string()
        ),
        session=session,
        tenant_id=tenant_id,
        sign_in_verifies_login_method=False,
        user_context=user_context,
    )


async def is_email_change_allowed(
    recipe_user_id: RecipeUserId,
    new_email: str,
    is_verified: bool,
    session: Optional[SessionContainer] = None,
    user_context: Optional[Dict[str, Any]] = None,
):
    if user_context is None:
        user_context = {}
    user = await get_user(recipe_user_id.get_as_string(), user_context)
    if user is None:
        raise Exception("Passed in recipe user id does not exist")

    res = await AccountLinkingRecipe.get_instance().is_email_change_allowed(
        user=user,
        new_email=new_email,
        is_verified=is_verified,
        session=session,
        user_context=user_context,
    )
    return res.allowed
