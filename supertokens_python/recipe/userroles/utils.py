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

from typing import TYPE_CHECKING, Callable, Union, Optional

from supertokens_python.recipe.userroles.interfaces import APIInterface, RecipeInterface
from supertokens_python.supertokens import AppInfo

if TYPE_CHECKING:
    from supertokens_python.recipe.userroles.recipe import UserRolesRecipe


class InputOverrideConfig:
    def __init__(
        self,
        functions: Union[Callable[[RecipeInterface], RecipeInterface], None] = None,
        apis: Union[Callable[[APIInterface], APIInterface], None] = None,
    ):
        self.functions = functions
        self.apis = apis


class UserRolesConfig:
    def __init__(
        self,
        skip_adding_roles_to_access_token: bool,
        skip_adding_permissions_to_access_token: bool,
        override: InputOverrideConfig,
    ) -> None:
        self.skip_adding_roles_to_access_token = skip_adding_roles_to_access_token
        self.skip_adding_permissions_to_access_token = (
            skip_adding_permissions_to_access_token
        )
        self.override = override


def validate_and_normalise_user_input(
    _recipe: UserRolesRecipe,
    _app_info: AppInfo,
    skip_adding_roles_to_access_token: Optional[bool] = None,
    skip_adding_permissions_to_access_token: Optional[bool] = None,
    override: Union[InputOverrideConfig, None] = None,
) -> UserRolesConfig:
    if override is not None and not isinstance(override, InputOverrideConfig):  # type: ignore
        raise ValueError("override must be an instance of InputOverrideConfig or None")

    if override is None:
        override = InputOverrideConfig()

    if skip_adding_roles_to_access_token is None:
        skip_adding_roles_to_access_token = False
    if skip_adding_permissions_to_access_token is None:
        skip_adding_permissions_to_access_token = False

    return UserRolesConfig(
        skip_adding_roles_to_access_token=skip_adding_roles_to_access_token,
        skip_adding_permissions_to_access_token=skip_adding_permissions_to_access_token,
        override=override,
    )
