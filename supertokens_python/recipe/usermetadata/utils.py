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

from supertokens_python.recipe.usermetadata.interfaces import (
    APIInterface,
    RecipeInterface,
)
from supertokens_python.types.config import (
    BaseConfig,
    BaseInputConfig,
    BaseInputOverrideConfig,
    BaseOverrideConfig,
)
from supertokens_python.types.utils import UseDefaultIfNone

if TYPE_CHECKING:
    from supertokens_python.recipe.usermetadata.recipe import UserMetadataRecipe
    from supertokens_python.supertokens import AppInfo


class InputOverrideConfig(BaseInputOverrideConfig[RecipeInterface, APIInterface]): ...


class OverrideConfig(BaseOverrideConfig[RecipeInterface, APIInterface]): ...


class UserMetadataInputConfig(BaseInputConfig[RecipeInterface, APIInterface]):
    override: UseDefaultIfNone[Optional[InputOverrideConfig]] = InputOverrideConfig()  # type: ignore - https://github.com/microsoft/pyright/issues/5933


class UserMetadataConfig(BaseConfig[RecipeInterface, APIInterface]):
    override: OverrideConfig  # type: ignore - https://github.com/microsoft/pyright/issues/5933


def validate_and_normalise_user_input(
    _recipe: UserMetadataRecipe,
    _app_info: AppInfo,
    input_config: UserMetadataInputConfig,
) -> UserMetadataConfig:
    override_config = OverrideConfig()
    if input_config.override is not None:
        if input_config.override.functions is not None:
            override_config.functions = input_config.override.functions

        if input_config.override.apis is not None:
            override_config.apis = input_config.override.apis

    return UserMetadataConfig(override=override_config)
