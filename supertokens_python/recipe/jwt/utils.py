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
    BaseInputConfig,
    BaseInputOverrideConfig,
    BaseOverrideConfig,
)
from supertokens_python.types.utils import UseDefaultIfNone

from .interfaces import APIInterface, RecipeInterface


class InputOverrideConfig(BaseInputOverrideConfig[RecipeInterface, APIInterface]): ...


class OverrideConfig(BaseOverrideConfig[RecipeInterface, APIInterface]): ...


class JWTInputConfig(BaseInputConfig[RecipeInterface, APIInterface]):
    jwt_validity_seconds: Optional[int] = None
    override: UseDefaultIfNone[Optional[InputOverrideConfig]] = InputOverrideConfig()  # type: ignore - https://github.com/microsoft/pyright/issues/5933


class JWTConfig(BaseConfig[RecipeInterface, APIInterface]):
    jwt_validity_seconds: int
    override: OverrideConfig  # type: ignore - https://github.com/microsoft/pyright/issues/5933


def validate_and_normalise_user_input(input_config: JWTInputConfig):
    override_config = OverrideConfig()
    if input_config.override is not None:
        if input_config.override.functions is not None:
            override_config.functions = input_config.override.functions

        if input_config.override.apis is not None:
            override_config.apis = input_config.override.apis

    jwt_validity_seconds = input_config.jwt_validity_seconds

    if input_config.jwt_validity_seconds is None:
        jwt_validity_seconds = 3153600000

    if not isinstance(jwt_validity_seconds, int):  # type: ignore
        raise ValueError("jwt_validity_seconds must be an integer or None")

    return JWTConfig(
        jwt_validity_seconds=jwt_validity_seconds, override=override_config
    )
