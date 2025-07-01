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

from typing import TYPE_CHECKING, Any, Dict, Optional, Union

from supertokens_python.recipe.accountlinking.types import (
    AccountInfoWithRecipeIdAndUserId,
    AccountLinkingConfig,
    NormalisedAccountLinkingConfig,
    NormalisedAccountLinkingOverrideConfig,
    RecipeLevelUser,
    ShouldAutomaticallyLink,
    ShouldNotAutomaticallyLink,
)

if TYPE_CHECKING:
    from supertokens_python.recipe.session.interfaces import SessionContainer
    from supertokens_python.supertokens import AppInfo
    from supertokens_python.types.base import User


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
    config: AccountLinkingConfig,
) -> NormalisedAccountLinkingConfig:
    global _did_use_default_should_do_automatic_account_linking

    override_config: NormalisedAccountLinkingOverrideConfig = (
        NormalisedAccountLinkingOverrideConfig()
    )

    if config.override is not None and config.override.functions is not None:
        override_config.functions = config.override.functions

    _did_use_default_should_do_automatic_account_linking = (
        config.should_do_automatic_account_linking is None
    )

    return NormalisedAccountLinkingConfig(
        override=override_config,
        on_account_linked=(
            default_on_account_linked
            if config.on_account_linked is None
            else config.on_account_linked
        ),
        should_do_automatic_account_linking=(
            default_should_do_automatic_account_linking
            if config.should_do_automatic_account_linking is None
            else config.should_do_automatic_account_linking
        ),
    )
