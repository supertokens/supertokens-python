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

from typing import Callable, Union, Optional, Dict, Any, Awaitable

from . import types

from . import utils
from .recipe import AccountLinkingRecipe

InputOverrideConfig = utils.InputOverrideConfig
AccountLinkingUser = types.User
RecipeLevelUser = types.RecipeLevelUser
AccountInfoWithRecipeIdAndUserId = types.AccountInfoWithRecipeIdAndUserId
SessionContainer = types.SessionContainer
ShouldAutomaticallyLink = types.ShouldAutomaticallyLink
ShouldNotAutomaticallyLink = types.ShouldNotAutomaticallyLink


def init(
    on_account_linked: Optional[
        Callable[[AccountLinkingUser, RecipeLevelUser, Dict[str, Any]], Awaitable[None]]
    ] = None,
    should_do_automatic_account_linking: Optional[
        Callable[
            [
                AccountInfoWithRecipeIdAndUserId,
                Optional[AccountLinkingUser],
                Optional[SessionContainer],
                str,
                Dict[str, Any],
            ],
            Awaitable[Union[ShouldNotAutomaticallyLink, ShouldAutomaticallyLink]],
        ]
    ] = None,
    override: Optional[InputOverrideConfig] = None,
):
    return AccountLinkingRecipe.init(
        on_account_linked, should_do_automatic_account_linking, override
    )
