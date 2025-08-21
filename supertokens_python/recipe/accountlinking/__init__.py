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

from supertokens_python.types import User

from .recipe import AccountLinkingRecipe
from .types import (
    AccountInfoWithRecipeIdAndUserId,
    AccountLinkingOverrideConfig,
    InputOverrideConfig,
    RecipeLevelUser,
    ShouldAutomaticallyLink,
    ShouldNotAutomaticallyLink,
)

if TYPE_CHECKING:
    from ..session.interfaces import SessionContainer


def init(
    on_account_linked: Optional[
        Callable[[User, RecipeLevelUser, Dict[str, Any]], Awaitable[None]]
    ] = None,
    should_do_automatic_account_linking: Optional[
        Callable[
            [
                AccountInfoWithRecipeIdAndUserId,
                Optional[User],
                Optional[SessionContainer],
                str,
                Dict[str, Any],
            ],
            Awaitable[Union[ShouldNotAutomaticallyLink, ShouldAutomaticallyLink]],
        ]
    ] = None,
    override: Optional[AccountLinkingOverrideConfig] = None,
):
    return AccountLinkingRecipe.init(
        on_account_linked, should_do_automatic_account_linking, override
    )


__all__ = [
    "AccountInfoWithRecipeIdAndUserId",
    "AccountLinkingOverrideConfig",
    "AccountLinkingRecipe",
    "InputOverrideConfig",  # deprecated, use AccountLinkingOverrideConfig instead
    "RecipeLevelUser",
    "ShouldAutomaticallyLink",
    "ShouldNotAutomaticallyLink",
    "init",
]
