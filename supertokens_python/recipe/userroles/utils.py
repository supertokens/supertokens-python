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

from typing import TYPE_CHECKING, Optional

from supertokens_python.recipe.userroles.interfaces import APIInterface, RecipeInterface
from supertokens_python.supertokens import AppInfo
from supertokens_python.types.config import (
    BaseConfig,
    BaseNormalisedConfig,
    BaseNormalisedOverrideConfig,
    BaseOverrideableConfig,
    BaseOverrideConfig,
)

if TYPE_CHECKING:
    from supertokens_python.recipe.userroles.recipe import UserRolesRecipe


UserRolesOverrideConfig = BaseOverrideConfig[RecipeInterface, APIInterface]
NormalisedUserRolesOverrideConfig = BaseNormalisedOverrideConfig[
    RecipeInterface, APIInterface
]
InputOverrideConfig = UserRolesOverrideConfig
"""Deprecated: Use `UserRolesOverrideConfig` instead."""


class UserRolesOverrideableConfig(BaseOverrideableConfig):
    """Input config properties overrideable using the plugin config overrides"""

    skip_adding_roles_to_access_token: Optional[bool] = None
    skip_adding_permissions_to_access_token: Optional[bool] = None


class UserRolesConfig(
    UserRolesOverrideableConfig,
    BaseConfig[RecipeInterface, APIInterface, UserRolesOverrideableConfig],
):
    def to_overrideable_config(self) -> UserRolesOverrideableConfig:
        """Create a `UserRolesOverrideableConfig` from the current config."""
        return UserRolesOverrideableConfig(**self.model_dump())

    def from_overrideable_config(
        self,
        overrideable_config: UserRolesOverrideableConfig,
    ) -> "UserRolesConfig":
        """
        Create a `UserRolesConfig` from a `UserRolesOverrideableConfig`.
        Not a classmethod since it needs to be used in a dynamic context within plugins.
        """
        return UserRolesConfig(
            **overrideable_config.model_dump(),
            override=self.override,
        )


class NormalisedUserRolesConfig(BaseNormalisedConfig[RecipeInterface, APIInterface]):
    skip_adding_roles_to_access_token: bool
    skip_adding_permissions_to_access_token: bool


def validate_and_normalise_user_input(
    _recipe: UserRolesRecipe,
    _app_info: AppInfo,
    config: UserRolesConfig,
) -> NormalisedUserRolesConfig:
    override_config = NormalisedUserRolesOverrideConfig.from_input_config(
        override_config=config.override
    )

    skip_adding_roles_to_access_token = config.skip_adding_roles_to_access_token
    if skip_adding_roles_to_access_token is None:
        skip_adding_roles_to_access_token = False

    skip_adding_permissions_to_access_token = (
        config.skip_adding_permissions_to_access_token
    )
    if skip_adding_permissions_to_access_token is None:
        skip_adding_permissions_to_access_token = False

    return NormalisedUserRolesConfig(
        skip_adding_roles_to_access_token=skip_adding_roles_to_access_token,
        skip_adding_permissions_to_access_token=skip_adding_permissions_to_access_token,
        override=override_config,
    )
