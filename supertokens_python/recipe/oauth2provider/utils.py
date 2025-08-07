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

OAuth2ProviderOverrideConfig = BaseOverrideConfig[RecipeInterface, APIInterface]
NormalisedOAuth2ProviderOverrideConfig = BaseNormalisedOverrideConfig[
    RecipeInterface, APIInterface
]
InputOverrideConfig = OAuth2ProviderOverrideConfig
"""Deprecated, use `OAuth2ProviderOverrideConfig` instead."""


class OAuth2ProviderOverrideableConfig(BaseOverrideableConfig):
    """Input config properties overrideable using the plugin config overrides"""

    ...


class OAuth2ProviderConfig(
    OAuth2ProviderOverrideableConfig,
    BaseConfig[RecipeInterface, APIInterface, OAuth2ProviderOverrideableConfig],
):
    def to_overrideable_config(self) -> OAuth2ProviderOverrideableConfig:
        """Create a `OAuth2ProviderOverrideableConfig` from the current config."""
        return OAuth2ProviderOverrideableConfig(**self.model_dump())

    def from_overrideable_config(
        self,
        overrideable_config: OAuth2ProviderOverrideableConfig,
    ) -> "OAuth2ProviderConfig":
        """
        Create a `OAuth2ProviderConfig` from a `OAuth2ProviderOverrideableConfig`.
        Not a classmethod since it needs to be used in a dynamic context within plugins.
        """
        return OAuth2ProviderConfig(
            **overrideable_config.model_dump(),
            override=self.override,
        )


class NormalisedOAuth2ProviderConfig(
    BaseNormalisedConfig[RecipeInterface, APIInterface]
): ...


def validate_and_normalise_user_input(config: OAuth2ProviderConfig):
    override_config = NormalisedOAuth2ProviderOverrideConfig.from_input_config(
        override_config=config.override
    )

    return NormalisedOAuth2ProviderConfig(override=override_config)
