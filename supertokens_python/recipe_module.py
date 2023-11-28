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
import re
from typing import TYPE_CHECKING, List, Union, Optional, Dict, Any, Callable, Awaitable
from typing_extensions import Literal

from .framework.response import BaseResponse

if TYPE_CHECKING:
    from supertokens_python.framework.request import BaseRequest
    from .supertokens import AppInfo


from .exceptions import SuperTokensError
from .normalised_url_path import NormalisedURLPath


class ApiIdWithTenantId:
    def __init__(self, api_id: str, tenant_id: str):
        self.api_id = api_id
        self.tenant_id = tenant_id


class RecipeModule(abc.ABC):
    get_tenant_id: Optional[Callable[[str, Dict[str, Any]], Awaitable[str]]] = None

    def __init__(self, recipe_id: str, app_info: AppInfo):
        self.recipe_id = recipe_id
        self.app_info = app_info

    def get_recipe_id(self):
        return self.recipe_id

    def get_app_info(self):
        return self.app_info

    async def return_api_id_if_can_handle_request(
        self, path: NormalisedURLPath, method: str, user_context: Dict[str, Any]
    ) -> Union[ApiIdWithTenantId, None]:
        from supertokens_python.recipe.multitenancy.constants import DEFAULT_TENANT_ID

        apis_handled = self.get_apis_handled()

        base_path_str = self.app_info.api_base_path.get_as_string_dangerous()
        path_str = path.get_as_string_dangerous()
        regex = rf"^{base_path_str}(?:/([a-zA-Z0-9-]+))?(/.*)$"

        match = re.match(regex, path_str)
        match_group_1 = match.group(1) if match is not None else None
        match_group_2 = match.group(2) if match is not None else None

        tenant_id: str = DEFAULT_TENANT_ID
        remaining_path: Optional[NormalisedURLPath] = None

        if (
            match is not None
            and isinstance(match_group_1, str)
            and isinstance(match_group_2, str)
        ):
            tenant_id = match_group_1
            remaining_path = NormalisedURLPath(match_group_2)

        assert RecipeModule.get_tenant_id is not None
        assert callable(RecipeModule.get_tenant_id)

        for current_api in apis_handled:
            if not current_api.disabled and current_api.method == method:
                if self.app_info.api_base_path.append(
                    current_api.path_without_api_base_path
                ).equals(path):
                    final_tenant_id = await RecipeModule.get_tenant_id(  # pylint: disable=not-callable
                        DEFAULT_TENANT_ID, user_context
                    )
                    return ApiIdWithTenantId(current_api.request_id, final_tenant_id)

                if remaining_path is not None and self.app_info.api_base_path.append(
                    current_api.path_without_api_base_path
                ).equals(self.app_info.api_base_path.append(remaining_path)):
                    final_tenant_id = await RecipeModule.get_tenant_id(  # pylint: disable=not-callable
                        tenant_id, user_context
                    )
                    return ApiIdWithTenantId(current_api.request_id, final_tenant_id)

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
        tenant_id: str,
        request: BaseRequest,
        path: NormalisedURLPath,
        method: str,
        response: BaseResponse,
        user_context: Dict[str, Any],
    ) -> Union[BaseResponse, None]:
        pass

    @abc.abstractmethod
    async def handle_error(
        self,
        request: BaseRequest,
        err: SuperTokensError,
        response: BaseResponse,
        user_context: Dict[str, Any],
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
