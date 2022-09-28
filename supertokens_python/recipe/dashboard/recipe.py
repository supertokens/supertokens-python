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

from os import environ
from typing import TYPE_CHECKING, List, Union, Optional, Callable, Awaitable

from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.recipe_module import APIHandled, RecipeModule
from .api import (
    api_key_protector,
    handle_dashboard_api,
    handle_users_get_api,
    handle_users_count_get_api,
    handle_validate_key_api,
)

from .api.implementation import APIImplementation
from .exceptions import SuperTokensDashboardError
from .interfaces import APIOptions, APIInterface
from .recipe_implementation import RecipeImplementation

if TYPE_CHECKING:
    from supertokens_python.framework.request import BaseRequest
    from supertokens_python.framework.response import BaseResponse
    from supertokens_python.supertokens import AppInfo

from supertokens_python.exceptions import SuperTokensError, raise_general_exception

from .constants import (
    DASHBOARD_API,
    VALIDATE_KEY_API,
    USERS_LIST_GET_API,
    USERS_COUNT_API,
)
from .utils import (
    InputOverrideConfig,
    validate_and_normalise_user_input,
    get_api_if_matched,
    is_api_path,
)


class DashboardRecipe(RecipeModule):
    recipe_id = "dashboard"
    __instance = None

    def __init__(
        self,
        recipe_id: str,
        app_info: AppInfo,
        api_key: str,
        override: Union[InputOverrideConfig, None] = None,
    ):
        super().__init__(recipe_id, app_info)
        self.config = validate_and_normalise_user_input(
            api_key,
            override,
        )
        recipe_implementation = RecipeImplementation()
        self.recipe_implementation = (
            recipe_implementation
            if self.config.override.functions is None
            else self.config.override.functions(recipe_implementation)
        )

        api_implementation = APIImplementation()
        self.api_implementation = (
            api_implementation
            if self.config.override.apis is None
            else self.config.override.apis(api_implementation)
        )

    def is_error_from_this_recipe_based_on_instance(self, err: Exception) -> bool:
        return isinstance(err, SuperTokensError) and (
            isinstance(err, SuperTokensDashboardError)
        )

    def get_apis_handled(self) -> List[APIHandled]:
        # Normally this array is used by the SDK to decide whether the recipe
        # handles a specific API path and method and then returns the ID.

        # However, for the dashboard recipe this logic is fully custom and handled inside the
        # `return_api_id_if_can_handle_request` method of this class. Since this array is never
        # used for this recipe, we simply return an empty array.

        return []

    async def handle_api_request(
        self,
        request_id: str,
        request: BaseRequest,
        path: NormalisedURLPath,
        method: str,
        response: BaseResponse,
    ) -> Optional[BaseResponse]:
        api_options = APIOptions(
            request,
            response,
            self.recipe_id,
            self.config,
            self.recipe_implementation,
            self.get_app_info(),
        )
        # For these APIs we dont need API key validation
        if request_id == DASHBOARD_API:
            return await handle_dashboard_api(self.api_implementation, api_options)
        if request_id == VALIDATE_KEY_API:
            return await handle_validate_key_api(self.api_implementation, api_options)

        # Do API key validation for the remaining APIs
        api_function: Optional[
            Callable[[APIInterface, APIOptions], Awaitable[Optional[BaseResponse]]]
        ] = None
        if request_id == USERS_LIST_GET_API:
            api_function = handle_users_get_api
        if request_id == USERS_COUNT_API:
            api_function = handle_users_count_get_api

        if api_function is not None:
            return await api_key_protector(
                self.api_implementation, api_options, api_function
            )

        return None

    async def handle_error(
        self, request: BaseRequest, err: SuperTokensError, response: BaseResponse
    ) -> BaseResponse:
        raise err

    def get_all_cors_headers(self) -> List[str]:
        return []

    @staticmethod
    def init(
        api_key: str,
        override: Union[InputOverrideConfig, None] = None,
    ):
        def func(app_info: AppInfo):
            if DashboardRecipe.__instance is None:
                DashboardRecipe.__instance = DashboardRecipe(
                    DashboardRecipe.recipe_id,
                    app_info,
                    api_key,
                    override,
                )
                return DashboardRecipe.__instance
            raise Exception(
                None,
                "Dashboard recipe has already been initialised. Please check your code for bugs.",
            )

        return func

    @staticmethod
    def get_instance() -> DashboardRecipe:
        if DashboardRecipe.__instance is not None:
            return DashboardRecipe.__instance
        raise_general_exception(
            "Initialisation not done. Did you forget to call the SuperTokens.init function?"
        )

    @staticmethod
    def reset():
        if ("SUPERTOKENS_ENV" not in environ) or (
            environ["SUPERTOKENS_ENV"] != "testing"
        ):
            raise_general_exception("calling testing function in non testing env")
        DashboardRecipe.__instance = None

    def return_api_id_if_can_handle_request(
        self, path: NormalisedURLPath, method: str
    ) -> Union[str, None]:
        dashboard_bundle_path = self.app_info.api_base_path.append(
            NormalisedURLPath(DASHBOARD_API)
        )

        if is_api_path(path, self.app_info):
            return get_api_if_matched(path, method)

        if path.startswith(dashboard_bundle_path):
            return DASHBOARD_API

        return None
