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
    BaseOverrideConfig,
)

from .interfaces import APIInterface, RecipeInterface

JWTOverrideConfig = BaseOverrideConfig[RecipeInterface, APIInterface]
NormalisedJWTOverrideConfig = BaseNormalisedOverrideConfig[
    RecipeInterface, APIInterface
]


class JWTConfig(BaseConfig[RecipeInterface, APIInterface]):
    jwt_validity_seconds: Optional[int] = None


class NormalisedJWTConfig(BaseNormalisedConfig[RecipeInterface, APIInterface]):
    jwt_validity_seconds: int


def validate_and_normalise_user_input(config: JWTConfig):
    override_config = NormalisedJWTOverrideConfig()
    if config.override is not None:
        if config.override.functions is not None:
            override_config.functions = config.override.functions

        if config.override.apis is not None:
            override_config.apis = config.override.apis

    jwt_validity_seconds = config.jwt_validity_seconds

    if config.jwt_validity_seconds is None:
        jwt_validity_seconds = 3153600000

    if not isinstance(jwt_validity_seconds, int):  # type: ignore
        raise ValueError("jwt_validity_seconds must be an integer or None")

    return NormalisedJWTConfig(
        jwt_validity_seconds=jwt_validity_seconds, override=override_config
    )
