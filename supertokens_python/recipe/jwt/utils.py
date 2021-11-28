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
from typing import TYPE_CHECKING, Callable, Union

if TYPE_CHECKING:
    from .interfaces import RecipeInterface, APIInterface


class OverrideConfig:
    def __init__(self, functions: Union[Callable[[RecipeInterface], RecipeInterface],
                                        None] = None, apis: Union[Callable[[APIInterface], APIInterface], None] = None):
        self.functions = functions
        self.apis = apis


class JWTConfig:
    def __init__(self, override: OverrideConfig, jwt_validity_seconds: int):
        self.override = override
        self.jwt_validity_seconds = jwt_validity_seconds


def validate_and_normalise_user_input(
        jwt_validity_seconds: Union[int, None] = None,
        override: Union[OverrideConfig, None] = None):
    if override is None:
        override = OverrideConfig()
    if jwt_validity_seconds is None:
        jwt_validity_seconds = 3153600000

    return JWTConfig(override, jwt_validity_seconds)
