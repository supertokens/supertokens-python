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

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Dict, Callable, Awaitable, Optional

from ...supertokens import AppInfo

from .utils import DashboardConfig

if TYPE_CHECKING:
    from supertokens_python.framework import BaseRequest, BaseResponse


class RecipeInterface(ABC):
    def __init__(self):
        pass

    @abstractmethod
    async def get_dashboard_bundle_location(self, user_context: Dict[str, Any]) -> str:
        pass

    @abstractmethod
    async def should_allow_access(
        self,
        request: BaseRequest,
        config: DashboardConfig,
        user_context: Dict[str, Any],
    ) -> bool:
        pass


class APIOptions:
    def __init__(
        self,
        request: BaseRequest,
        response: BaseResponse,
        recipe_id: str,
        config: DashboardConfig,
        recipe_implementation: RecipeInterface,
        app_info: AppInfo,
    ):
        self.request: BaseRequest = request
        self.response: BaseResponse = response
        self.recipe_id: str = recipe_id
        self.config: DashboardConfig = config
        self.recipe_implementation: RecipeInterface = recipe_implementation
        self.app_info = app_info


class APIInterface:
    def __init__(self):
        # undefined should be allowed
        self.dashboard_get: Optional[
            Callable[[APIOptions, Dict[str, Any]], Awaitable[str]]
        ] = None
