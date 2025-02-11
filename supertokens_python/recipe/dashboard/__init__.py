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

from typing import Callable, List, Optional

from supertokens_python import AppInfo, RecipeModule
from supertokens_python.recipe.dashboard import utils

from .recipe import DashboardRecipe

InputOverrideConfig = utils.InputOverrideConfig


def init(
    api_key: Optional[str] = None,
    admins: Optional[List[str]] = None,
    override: Optional[InputOverrideConfig] = None,
) -> Callable[[AppInfo], RecipeModule]:
    return DashboardRecipe.init(
        api_key,
        admins,
        override,
    )
