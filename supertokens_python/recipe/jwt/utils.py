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

from typing import Optional

from supertokens_python.types.config import (
    BaseConfig,
    BaseNormalisedConfig,
    BaseNormalisedOverrideConfig,
    BaseOverrideableConfig,
    BaseOverrideConfig,
)

from .interfaces import APIInterface, RecipeInterface

JWTOverrideConfig = BaseOverrideConfig[RecipeInterface, APIInterface]
NormalisedJWTOverrideConfig = BaseNormalisedOverrideConfig[
    RecipeInterface, APIInterface
]
OverrideConfig = JWTOverrideConfig
"""Deprecated, use `JWTOverrideConfig` instead."""


class JWTOverrideableConfig(BaseOverrideableConfig):
    """Input config properties overrideable using the plugin config overrides"""

    jwt_validity_seconds: Optional[int] = None


class JWTConfig(
    JWTOverrideableConfig,
    BaseConfig[RecipeInterface, APIInterface, JWTOverrideableConfig],
):
    def to_overrideable_config(self) -> JWTOverrideableConfig:
        """Create a `JWTOverrideableConfig` from the current config."""
        return JWTOverrideableConfig(**self.model_dump())

    def from_overrideable_config(
        self,
        overrideable_config: JWTOverrideableConfig,
    ) -> "JWTConfig":
        """
        Create a `JWTConfig` from a `JWTOverrideableConfig`.
        Not a classmethod since it needs to be used in a dynamic context within plugins.
        """
        return JWTConfig(
            **overrideable_config.model_dump(),
            override=self.override,
        )


class NormalisedJWTConfig(BaseNormalisedConfig[RecipeInterface, APIInterface]):
    jwt_validity_seconds: int


def validate_and_normalise_user_input(config: JWTConfig):
    override_config = NormalisedJWTOverrideConfig.from_input_config(
        override_config=config.override
    )

    jwt_validity_seconds = config.jwt_validity_seconds

    if config.jwt_validity_seconds is None:
        jwt_validity_seconds = 3153600000

    if not isinstance(jwt_validity_seconds, int):  # type: ignore
        raise ValueError("jwt_validity_seconds must be an integer or None")

    return NormalisedJWTConfig(
        jwt_validity_seconds=jwt_validity_seconds, override=override_config
    )
