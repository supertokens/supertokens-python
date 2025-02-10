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

from typing import Any, Dict, List, Optional

from supertokens_python.recipe.accountlinking.asyncio import get_user
from supertokens_python.recipe.session import SessionContainer

from ..types import (
    MFARequirementList,
)
from ..utils import update_and_get_mfa_related_info_in_session


async def assert_allowed_to_setup_factor_else_throw_invalid_claim_error(
    session: SessionContainer,
    factor_id: str,
    user_context: Optional[Dict[str, Any]] = None,
) -> None:
    if user_context is None:
        user_context = {}

    mfa_info = await update_and_get_mfa_related_info_in_session(
        input_session=session,
        user_context=user_context,
    )
    factors_set_up_for_user = await get_factors_setup_for_user(
        session.get_user_id(), user_context
    )
    from ..recipe import MultiFactorAuthRecipe

    recipe = MultiFactorAuthRecipe.get_instance_or_throw_error()

    async def func_factors_set_up_for_user():
        return factors_set_up_for_user

    async def func_mfa_requirements_for_auth():
        return mfa_info.mfa_requirements_for_auth

    await recipe.recipe_implementation.assert_allowed_to_setup_factor_else_throw_invalid_claim_error(
        session=session,
        factor_id=factor_id,
        factors_set_up_for_user=func_factors_set_up_for_user,
        mfa_requirements_for_auth=func_mfa_requirements_for_auth,
        user_context=user_context,
    )


async def get_mfa_requirements_for_auth(
    session: SessionContainer,
    user_context: Optional[Dict[str, Any]] = None,
) -> MFARequirementList:
    if user_context is None:
        user_context = {}

    mfa_info = await update_and_get_mfa_related_info_in_session(
        input_session=session,
        user_context=user_context,
    )

    return mfa_info.mfa_requirements_for_auth


async def mark_factor_as_complete_in_session(
    session: SessionContainer,
    factor_id: str,
    user_context: Optional[Dict[str, Any]] = None,
) -> None:
    if user_context is None:
        user_context = {}
    from ..recipe import MultiFactorAuthRecipe

    recipe = MultiFactorAuthRecipe.get_instance_or_throw_error()
    await recipe.recipe_implementation.mark_factor_as_complete_in_session(
        session=session,
        factor_id=factor_id,
        user_context=user_context,
    )


async def get_factors_setup_for_user(
    user_id: str,
    user_context: Optional[Dict[str, Any]] = None,
) -> List[str]:
    if user_context is None:
        user_context = {}

    user = await get_user(user_id, user_context)
    if user is None:
        raise Exception("Unknown user id")
    from ..recipe import MultiFactorAuthRecipe

    recipe = MultiFactorAuthRecipe.get_instance_or_throw_error()
    return await recipe.recipe_implementation.get_factors_setup_for_user(
        user=user,
        user_context=user_context,
    )


async def get_required_secondary_factors_for_user(
    user_id: str,
    user_context: Optional[Dict[str, Any]] = None,
) -> List[str]:
    if user_context is None:
        user_context = {}
    from ..recipe import MultiFactorAuthRecipe

    recipe = MultiFactorAuthRecipe.get_instance_or_throw_error()
    return await recipe.recipe_implementation.get_required_secondary_factors_for_user(
        user_id=user_id,
        user_context=user_context,
    )


async def add_to_required_secondary_factors_for_user(
    user_id: str,
    factor_id: str,
    user_context: Optional[Dict[str, Any]] = None,
) -> None:
    if user_context is None:
        user_context = {}
    from ..recipe import MultiFactorAuthRecipe

    recipe = MultiFactorAuthRecipe.get_instance_or_throw_error()
    await recipe.recipe_implementation.add_to_required_secondary_factors_for_user(
        user_id=user_id,
        factor_id=factor_id,
        user_context=user_context,
    )


async def remove_from_required_secondary_factors_for_user(
    user_id: str,
    factor_id: str,
    user_context: Optional[Dict[str, Any]] = None,
) -> None:
    if user_context is None:
        user_context = {}
    from ..recipe import MultiFactorAuthRecipe

    recipe = MultiFactorAuthRecipe.get_instance_or_throw_error()
    await recipe.recipe_implementation.remove_from_required_secondary_factors_for_user(
        user_id=user_id,
        factor_id=factor_id,
        user_context=user_context,
    )
