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

from typing import TYPE_CHECKING, Callable, Optional, Union

if TYPE_CHECKING:
    from supertokens_python import AppInfo, RecipeModule
    from supertokens_python.recipe.dashboard.utils import InputOverrideConfig


def init(
    api_key: Union[str, None] = None,
    override: Optional[InputOverrideConfig] = None,
) -> Callable[[AppInfo], RecipeModule]:
    # Global import for the following was avoided because of circular import errors
    from .recipe import DashboardRecipe

    return DashboardRecipe.init(
        api_key,
        override,
    )
