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

import abc
from typing import TYPE_CHECKING, List, Union

from typing_extensions import Literal

from .framework.response import BaseResponse

if TYPE_CHECKING:
    from supertokens_python.framework.request import BaseRequest
    from .supertokens import AppInfo
    from .normalised_url_path import NormalisedURLPath

from .exceptions import SuperTokensError


class RecipeModule(abc.ABC):
    def __init__(self, recipe_id: str, app_info: AppInfo):
        self.recipe_id = recipe_id
        self.app_info = app_info

    def get_recipe_id(self):
        return self.recipe_id

    def get_app_info(self):
        return self.app_info

    def return_api_id_if_can_handle_request(
        self, path: NormalisedURLPath, method: str
    ) -> Union[str, None]:
        apis_handled = self.get_apis_handled()
        for current_api in apis_handled:
            if (
                not current_api.disabled
                and current_api.method == method
                and self.app_info.api_base_path.append(
                    current_api.path_without_api_base_path
                ).equals(path)
            ):
                return current_api.request_id
        return None

    @abc.abstractmethod
    def is_error_from_this_recipe_based_on_instance(self, err: Exception) -> bool:
        pass

    @abc.abstractmethod
    def get_apis_handled(self) -> List[APIHandled]:
        pass

    @abc.abstractmethod
    async def handle_api_request(
        self,
        request_id: str,
        request: BaseRequest,
        path: NormalisedURLPath,
        method: str,
        response: BaseResponse,
    ) -> Union[BaseResponse, None]:
        pass

    @abc.abstractmethod
    async def handle_error(
        self, request: BaseRequest, err: SuperTokensError, response: BaseResponse
    ) -> BaseResponse:
        pass

    @abc.abstractmethod
    def get_all_cors_headers(self) -> List[str]:
        pass


class APIHandled:
    def __init__(
        self,
        path_without_api_base_path: NormalisedURLPath,
        method: Literal["post", "get", "delete", "put", "options", "trace"],
        request_id: str,
        disabled: bool,
    ):
        self.path_without_api_base_path = path_without_api_base_path
        self.method = method
        self.request_id = request_id
        self.disabled = disabled
