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

from supertokens_python.types.config import (
    BaseConfig,
    BaseNormalisedConfig,
    BaseNormalisedOverrideConfig,
    BaseOverrideableConfig,
    BaseOverrideConfig,
)

from .interfaces import APIInterface, RecipeInterface

SAMLOverrideConfig = BaseOverrideConfig[RecipeInterface, APIInterface]
NormalisedSAMLOverrideConfig = BaseNormalisedOverrideConfig[
    RecipeInterface, APIInterface
]


class SAMLOverrideableConfig(BaseOverrideableConfig):
    """Input config properties overrideable using the plugin config overrides"""

    ...


class SAMLConfig(
    SAMLOverrideableConfig,
    BaseConfig[RecipeInterface, APIInterface, SAMLOverrideableConfig],
):
    def to_overrideable_config(self) -> SAMLOverrideableConfig:
        """Create a `SAMLOverrideableConfig` from the current config."""
        return SAMLOverrideableConfig(**self.model_dump())

    def from_overrideable_config(
        self,
        overrideable_config: SAMLOverrideableConfig,
    ) -> "SAMLConfig":
        """
        Create a `SAMLConfig` from a `SAMLOverrideableConfig`.
        Not a classmethod since it needs to be used in a dynamic context within plugins.
        """
        return SAMLConfig(
            **overrideable_config.model_dump(),
            override=self.override,
        )


class NormalisedSAMLConfig(BaseNormalisedConfig[RecipeInterface, APIInterface]): ...


def validate_and_normalise_user_input(config: SAMLConfig) -> NormalisedSAMLConfig:
    override_config = NormalisedSAMLOverrideConfig.from_input_config(
        override_config=config.override
    )

    return NormalisedSAMLConfig(override=override_config)
