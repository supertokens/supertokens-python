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

from supertokens_python.async_to_sync_wrapper import sync
from supertokens_python.recipe.session import SessionContainer


def assert_allowed_to_setup_factor_else_throw_invalid_claim_error(
    session: SessionContainer,
    factor_id: str,
    user_context: Optional[Dict[str, Any]] = None,
) -> None:
    if user_context is None:
        user_context = {}

    from supertokens_python.recipe.multifactorauth.asyncio import (
        assert_allowed_to_setup_factor_else_throw_invalid_claim_error as async_func,
    )

    return sync(async_func(session, factor_id, user_context))


def get_mfa_requirements_for_auth(
    session: SessionContainer,
    user_context: Optional[Dict[str, Any]] = None,
):
    if user_context is None:
        user_context = {}

    from supertokens_python.recipe.multifactorauth.asyncio import (
        get_mfa_requirements_for_auth as async_func,
    )

    return sync(async_func(session, user_context))


def mark_factor_as_complete_in_session(
    session: SessionContainer,
    factor_id: str,
    user_context: Optional[Dict[str, Any]] = None,
) -> None:
    if user_context is None:
        user_context = {}

    from supertokens_python.recipe.multifactorauth.asyncio import (
        mark_factor_as_complete_in_session as async_func,
    )

    return sync(async_func(session, factor_id, user_context))


def get_factors_setup_for_user(
    user_id: str,
    user_context: Optional[Dict[str, Any]] = None,
) -> List[str]:
    if user_context is None:
        user_context = {}

    from supertokens_python.recipe.multifactorauth.asyncio import (
        get_factors_setup_for_user as async_func,
    )

    return sync(async_func(user_id, user_context))


def get_required_secondary_factors_for_user(
    user_id: str,
    user_context: Optional[Dict[str, Any]] = None,
) -> List[str]:
    if user_context is None:
        user_context = {}

    from supertokens_python.recipe.multifactorauth.asyncio import (
        get_required_secondary_factors_for_user as async_func,
    )

    return sync(async_func(user_id, user_context))


def add_to_required_secondary_factors_for_user(
    user_id: str,
    factor_id: str,
    user_context: Optional[Dict[str, Any]] = None,
) -> None:
    if user_context is None:
        user_context = {}

    from supertokens_python.recipe.multifactorauth.asyncio import (
        add_to_required_secondary_factors_for_user as async_func,
    )

    return sync(async_func(user_id, factor_id, user_context))


def remove_from_required_secondary_factors_for_user(
    user_id: str,
    factor_id: str,
    user_context: Optional[Dict[str, Any]] = None,
) -> None:
    if user_context is None:
        user_context = {}

    from supertokens_python.recipe.multifactorauth.asyncio import (
        remove_from_required_secondary_factors_for_user as async_func,
    )

    return sync(async_func(user_id, factor_id, user_context))
