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

from typing import TYPE_CHECKING

from supertokens_python.recipe.usermetadata.interfaces import (
    APIInterface,
    RecipeInterface,
)
from supertokens_python.types.config import (
    BaseConfig,
    BaseNormalisedConfig,
    BaseNormalisedOverrideConfig,
    BaseOverrideConfig,
)

if TYPE_CHECKING:
    from supertokens_python.recipe.usermetadata.recipe import UserMetadataRecipe
    from supertokens_python.supertokens import AppInfo


UserMetadataOverrideConfig = BaseOverrideConfig[RecipeInterface, APIInterface]
NormalisedUserMetadataOverrideConfig = BaseNormalisedOverrideConfig[
    RecipeInterface, APIInterface
]
InputOverrideConfig = UserMetadataOverrideConfig
"""Deprecated: Use `UserMetadataOverrideConfig` instead."""


class UserMetadataConfig(BaseConfig[RecipeInterface, APIInterface]): ...


class NormalisedUserMetadataConfig(
    BaseNormalisedConfig[RecipeInterface, APIInterface]
): ...


def validate_and_normalise_user_input(
    _recipe: UserMetadataRecipe,
    _app_info: AppInfo,
    input_config: UserMetadataConfig,
) -> NormalisedUserMetadataConfig:
    override_config = NormalisedUserMetadataOverrideConfig.from_input_config(
        override_config=input_config.override
    )

    return NormalisedUserMetadataConfig(override=override_config)
