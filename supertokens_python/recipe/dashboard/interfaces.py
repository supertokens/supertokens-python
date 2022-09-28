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
from typing import TYPE_CHECKING, Any, Dict, Callable, Awaitable, Optional, List

from ...supertokens import AppInfo

from .utils import DashboardConfig
from ...types import User, APIResponse

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


class DashboardUsersGetResponse(APIResponse):
    status: str = "OK"

    def __init__(self, users: List[User], next_pagination_token: Optional[str]):
        self.users = users
        self.next_pagination_token = next_pagination_token

    def to_json(self) -> Dict[str, Any]:
        users_json = [
            {
                "recipeId": u.recipe_id,
                "user": {
                    "id": u.user_id,
                    "email": u.email,
                    "timeJoined": u.time_joined,
                    "thirdParty": None
                    if u.third_party_info is None
                    else u.third_party_info.__dict__,
                    "phoneNumber": u.phone_number,
                },
            }
            for u in self.users
        ]

        return {
            "status": self.status,
            "users": users_json,
            "nextPaginationToken": self.next_pagination_token,
        }
