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
    BaseInputConfig,
    BaseInputOverrideConfig,
    BaseOverrideConfig,
)
from supertokens_python.types.utils import UseDefaultIfNone

if TYPE_CHECKING:
    from supertokens_python.recipe.userroles.recipe import UserRolesRecipe


class InputOverrideConfig(BaseInputOverrideConfig[RecipeInterface, APIInterface]): ...


class OverrideConfig(BaseOverrideConfig[RecipeInterface, APIInterface]): ...


class UserRolesInputConfig(BaseInputConfig[RecipeInterface, APIInterface]):
    skip_adding_roles_to_access_token: Optional[bool] = None
    skip_adding_permissions_to_access_token: Optional[bool] = None
    override: UseDefaultIfNone[Optional[InputOverrideConfig]] = InputOverrideConfig()  # type: ignore - https://github.com/microsoft/pyright/issues/5933


class UserRolesConfig(BaseConfig[RecipeInterface, APIInterface]):
    skip_adding_roles_to_access_token: bool
    skip_adding_permissions_to_access_token: bool
    override: OverrideConfig  # type: ignore - https://github.com/microsoft/pyright/issues/5933


def validate_and_normalise_user_input(
    _recipe: UserRolesRecipe,
    _app_info: AppInfo,
    input_config: UserRolesInputConfig,
    # skip_adding_roles_to_access_token: Optional[bool] = None,
    # skip_adding_permissions_to_access_token: Optional[bool] = None,
    # override: Union[InputOverrideConfig, None] = None,
) -> UserRolesConfig:
    override_config = OverrideConfig()
    if input_config.override is not None:
        if input_config.override.functions is not None:
            override_config.functions = input_config.override.functions

        if input_config.override.apis is not None:
            override_config.apis = input_config.override.apis

    skip_adding_roles_to_access_token = input_config.skip_adding_roles_to_access_token
    if skip_adding_roles_to_access_token is None:
        skip_adding_roles_to_access_token = False

    skip_adding_permissions_to_access_token = (
        input_config.skip_adding_permissions_to_access_token
    )
    if skip_adding_permissions_to_access_token is None:
        skip_adding_permissions_to_access_token = False

    return UserRolesConfig(
        skip_adding_roles_to_access_token=skip_adding_roles_to_access_token,
        skip_adding_permissions_to_access_token=skip_adding_permissions_to_access_token,
        override=override_config,
    )
