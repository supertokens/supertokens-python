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

from typing import TYPE_CHECKING, Any, Awaitable, Callable, Dict, Optional, Union

if TYPE_CHECKING:
    from .types import (
        AccountInfoWithRecipeIdAndUserId,
        AccountLinkingConfig,
        InputOverrideConfig,
        RecipeLevelUser,
        SessionContainer,
        ShouldAutomaticallyLink,
        ShouldNotAutomaticallyLink,
        User,
    )

if TYPE_CHECKING:
    from supertokens_python.supertokens import AppInfo


async def default_on_account_linked(_: User, __: RecipeLevelUser, ___: Dict[str, Any]):
    pass


_did_use_default_should_do_automatic_account_linking: bool = True


async def default_should_do_automatic_account_linking(
    _: AccountInfoWithRecipeIdAndUserId,
    ___: Optional[User],
    ____: Optional[SessionContainer],
    _____: str,
    ______: Dict[str, Any],
) -> Union[ShouldNotAutomaticallyLink, ShouldAutomaticallyLink]:
    from .types import (
        ShouldNotAutomaticallyLink as SNAL,
    )

    return SNAL()


def recipe_init_defined_should_do_automatic_account_linking() -> bool:
    return not _did_use_default_should_do_automatic_account_linking


def validate_and_normalise_user_input(
    _: AppInfo,
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
    override: Union[InputOverrideConfig, None] = None,
) -> AccountLinkingConfig:
    from .types import (
        AccountLinkingConfig as ALC,
    )
    from .types import (
        InputOverrideConfig as IOC,
    )
    from .types import (
        OverrideConfig,
    )

    global _did_use_default_should_do_automatic_account_linking
    if override is None:
        override = IOC()

    _did_use_default_should_do_automatic_account_linking = (
        should_do_automatic_account_linking is None
    )

    return ALC(
        override=OverrideConfig(functions=override.functions),
        on_account_linked=(
            default_on_account_linked
            if on_account_linked is None
            else on_account_linked
        ),
        should_do_automatic_account_linking=(
            default_should_do_automatic_account_linking
            if should_do_automatic_account_linking is None
            else should_do_automatic_account_linking
        ),
    )
