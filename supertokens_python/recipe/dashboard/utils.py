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

from typing import Callable, Union, Optional, TYPE_CHECKING

from .constants import (
    DASHBOARD_API,
    VALIDATE_KEY_API,
    USERS_LIST_GET_API,
    USERS_COUNT_API,
)
from ...normalised_url_path import NormalisedURLPath
from ...supertokens import AppInfo

if TYPE_CHECKING:
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


def is_api_path(path: NormalisedURLPath, app_info: AppInfo) -> bool:
    dashboard_recipe_base_path = app_info.api_base_path.append(
        NormalisedURLPath(DASHBOARD_API)
    )

    if not path.startswith(dashboard_recipe_base_path):
        return False

    path_without_dashboard_path = path.get_as_string_dangerous().split(DASHBOARD_API)[1]

    if len(path_without_dashboard_path) > 0 and path_without_dashboard_path[0] == "/":
        path_without_dashboard_path = path_without_dashboard_path[1:]

    if path_without_dashboard_path.split("/")[0] == "api":
        return True

    return False


def get_api_if_matched(path: NormalisedURLPath, method: str) -> Optional[str]:
    path_str = path.get_as_string_dangerous()

    if path_str.endswith(VALIDATE_KEY_API) and method == "post":
        return VALIDATE_KEY_API
    if path_str.endswith(USERS_LIST_GET_API) and method == "get":
        return USERS_LIST_GET_API
    if path_str.endswith(USERS_COUNT_API) and method == "get":
        return USERS_COUNT_API

    return None
