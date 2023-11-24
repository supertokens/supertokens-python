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
from typing import List, Union, Optional, Dict, Any

from supertokens_python.exceptions import SuperTokensError, raise_general_exception
from supertokens_python.framework import BaseRequest, BaseResponse
from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.querier import Querier
from supertokens_python.recipe.usermetadata.exceptions import (
    SuperTokensUserMetadataError,
)
from supertokens_python.recipe.usermetadata.recipe_implementation import (
    RecipeImplementation,
)
from supertokens_python.recipe.usermetadata.utils import (
    validate_and_normalise_user_input,
)
from supertokens_python.recipe_module import APIHandled, RecipeModule
from supertokens_python.supertokens import AppInfo

from .utils import InputOverrideConfig


class UserMetadataRecipe(RecipeModule):
    recipe_id = "usermetadata"
    __instance = None

    def __init__(
        self,
        recipe_id: str,
        app_info: AppInfo,
        override: Union[InputOverrideConfig, None] = None,
    ):
        super().__init__(recipe_id, app_info)
        self.config = validate_and_normalise_user_input(self, app_info, override)
        recipe_implementation = RecipeImplementation(Querier.get_instance(recipe_id))
        self.recipe_implementation = (
            recipe_implementation
            if self.config.override.functions is None
            else self.config.override.functions(recipe_implementation)
        )

    def is_error_from_this_recipe_based_on_instance(self, err: Exception) -> bool:
        return isinstance(err, SuperTokensError) and (
            isinstance(err, SuperTokensUserMetadataError)
        )

    def get_apis_handled(self) -> List[APIHandled]:
        return []

    async def handle_api_request(
        self,
        request_id: str,
        tenant_id: Optional[str],
        request: BaseRequest,
        path: NormalisedURLPath,
        method: str,
        response: BaseResponse,
        user_context: Dict[str, Any],
    ) -> Union[BaseResponse, None]:
        raise Exception("Should never come here")

    async def handle_error(
        self,
        request: BaseRequest,
        err: SuperTokensError,
        response: BaseResponse,
        user_context: Dict[str, Any],
    ) -> BaseResponse:
        raise err

    def get_all_cors_headers(self) -> List[str]:
        return []

    @staticmethod
    def init(override: Union[InputOverrideConfig, None] = None):
        def func(app_info: AppInfo):
            if UserMetadataRecipe.__instance is None:
                UserMetadataRecipe.__instance = UserMetadataRecipe(
                    UserMetadataRecipe.recipe_id, app_info, override
                )
                return UserMetadataRecipe.__instance
            raise Exception(
                None,
                "Usermetadata recipe has already been initialised. Please check your code for bugs.",
            )

        return func

    @staticmethod
    def reset():
        if ("SUPERTOKENS_ENV" not in environ) or (
            environ["SUPERTOKENS_ENV"] != "testing"
        ):
            raise_general_exception("calling testing function in non testing env")
        UserMetadataRecipe.__instance = None

    @staticmethod
    def get_instance() -> UserMetadataRecipe:
        if UserMetadataRecipe.__instance is not None:
            return UserMetadataRecipe.__instance
        raise_general_exception(
            "Initialisation not done. Did you forget to call the SuperTokens.init function?"
        )
