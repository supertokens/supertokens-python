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

from supertokens_python.async_to_sync_wrapper import sync
from supertokens_python.recipe.session import SessionContainer
from supertokens_python.types import RecipeUserId

from ..types import AccountInfoWithRecipeId


def create_primary_user_id_or_link_accounts(
    tenant_id: str,
    recipe_user_id: RecipeUserId,
    session: Optional[SessionContainer] = None,
    user_context: Optional[Dict[str, Any]] = None,
):
    from ..asyncio import (
        create_primary_user_id_or_link_accounts as async_create_primary_user_id_or_link_accounts,
    )

    return sync(
        async_create_primary_user_id_or_link_accounts(
            tenant_id, recipe_user_id, session, user_context
        )
    )


def get_primary_user_that_can_be_linked_to_recipe_user_id(
    tenant_id: str,
    recipe_user_id: RecipeUserId,
    user_context: Optional[Dict[str, Any]] = None,
):
    from ..asyncio import (
        get_primary_user_that_can_be_linked_to_recipe_user_id as async_get_primary_user_that_can_be_linked_to_recipe_user_id,
    )

    return sync(
        async_get_primary_user_that_can_be_linked_to_recipe_user_id(
            tenant_id, recipe_user_id, user_context
        )
    )


def can_create_primary_user(
    recipe_user_id: RecipeUserId, user_context: Optional[Dict[str, Any]] = None
):
    from ..asyncio import can_create_primary_user as async_can_create_primary_user

    return sync(async_can_create_primary_user(recipe_user_id, user_context))


def create_primary_user(
    recipe_user_id: RecipeUserId, user_context: Optional[Dict[str, Any]] = None
):
    from ..asyncio import create_primary_user as async_create_primary_user

    return sync(async_create_primary_user(recipe_user_id, user_context))


def can_link_accounts(
    recipe_user_id: RecipeUserId,
    primary_user_id: str,
    user_context: Optional[Dict[str, Any]] = None,
):
    from ..asyncio import can_link_accounts as async_can_link_accounts

    return sync(async_can_link_accounts(recipe_user_id, primary_user_id, user_context))


def link_accounts(
    recipe_user_id: RecipeUserId,
    primary_user_id: str,
    user_context: Optional[Dict[str, Any]] = None,
):
    from ..asyncio import link_accounts as async_link_accounts

    return sync(async_link_accounts(recipe_user_id, primary_user_id, user_context))


def unlink_account(
    recipe_user_id: RecipeUserId, user_context: Optional[Dict[str, Any]] = None
):
    from ..asyncio import unlink_account as async_unlink_account

    return sync(async_unlink_account(recipe_user_id, user_context))


def is_sign_up_allowed(
    tenant_id: str,
    new_user: AccountInfoWithRecipeId,
    is_verified: bool,
    session: Optional[SessionContainer] = None,
    user_context: Optional[Dict[str, Any]] = None,
):
    from ..asyncio import is_sign_up_allowed as async_is_sign_up_allowed

    return sync(
        async_is_sign_up_allowed(
            tenant_id, new_user, is_verified, session, user_context
        )
    )


def is_sign_in_allowed(
    tenant_id: str,
    recipe_user_id: RecipeUserId,
    session: Optional[SessionContainer] = None,
    user_context: Optional[Dict[str, Any]] = None,
):
    from ..asyncio import is_sign_in_allowed as async_is_sign_in_allowed

    return sync(
        async_is_sign_in_allowed(tenant_id, recipe_user_id, session, user_context)
    )


def is_email_change_allowed(
    recipe_user_id: RecipeUserId,
    new_email: str,
    is_verified: bool,
    session: Optional[SessionContainer] = None,
    user_context: Optional[Dict[str, Any]] = None,
):
    from ..asyncio import is_email_change_allowed as async_is_email_change_allowed

    return sync(
        async_is_email_change_allowed(
            recipe_user_id, new_email, is_verified, session, user_context
        )
    )
