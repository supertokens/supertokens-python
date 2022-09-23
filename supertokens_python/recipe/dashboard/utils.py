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

from typing import Callable, Union, Optional

from .interfaces import APIInterface, RecipeInterface


class InputOverrideConfig:
    def __init__(
        self,
        functions: Union[Callable[[RecipeInterface], RecipeInterface], None] = None,
        apis: Union[Callable[[APIInterface], APIInterface], None] = None,
    ):
        self.functions = functions
        self.apis = apis


class OverrideConfig:
    def __init__(
        self,
        functions: Union[Callable[[RecipeInterface], RecipeInterface], None] = None,
        apis: Union[Callable[[APIInterface], APIInterface], None] = None,
    ):
        self.functions = functions
        self.apis = apis


class DashboardConfig:
    def __init__(
        self,
        api_key: str,
        override: OverrideConfig,
    ):
        self.api_key = api_key
        self.override = override


def validate_and_normalise_user_input(
    # app_info: AppInfo,
    api_key: str,
    override: Optional[InputOverrideConfig] = None,
) -> DashboardConfig:
    if api_key.strip() == "":
        raise Exception("apiKey provided to Dashboard recipe cannot be empty")

    if override is None:
        override = InputOverrideConfig()

    return DashboardConfig(
        api_key,
        OverrideConfig(
            functions=override.functions,
            apis=override.apis,
        ),
    )
