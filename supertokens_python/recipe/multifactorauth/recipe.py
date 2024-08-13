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
from typing import Any, Dict, Optional, List, Union

from supertokens_python.exceptions import SuperTokensError, raise_general_exception
from supertokens_python.framework import BaseRequest, BaseResponse
from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.recipe.multifactorauth.interfaces import RecipeInterface
from supertokens_python.recipe_module import APIHandled, RecipeModule
from supertokens_python.supertokens import AppInfo
from .types import OverrideConfig


class MultiFactorAuthRecipe(RecipeModule):
    recipe_id = "multifactorauth"
    __instance = None

    def __init__(
        self,
        recipe_id: str,
        app_info: AppInfo,
        first_factors: Optional[List[str]] = None,
        override: Union[OverrideConfig, None] = None,
    ):
        super().__init__(recipe_id, app_info)
        self.recipe_implementation: RecipeInterface

    def is_error_from_this_recipe_based_on_instance(self, err: Exception) -> bool:
        return False

    def get_apis_handled(self) -> List[APIHandled]:
        return []

    async def handle_api_request(
        self,
        request_id: str,
        tenant_id: str,
        request: BaseRequest,
        path: NormalisedURLPath,
        method: str,
        response: BaseResponse,
        user_context: Dict[str, Any],
    ):
        return None

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
    def init(
        first_factors: Optional[List[str]] = None,
        override: Union[OverrideConfig, None] = None,
    ):
        def func(app_info: AppInfo):
            if MultiFactorAuthRecipe.__instance is None:
                MultiFactorAuthRecipe.__instance = MultiFactorAuthRecipe(
                    MultiFactorAuthRecipe.recipe_id,
                    app_info,
                    first_factors,
                    override,
                )
                return MultiFactorAuthRecipe.__instance
            raise_general_exception(
                "MultiFactorAuthRecipe recipe has already been initialised. Please check your code for bugs."
            )

        return func

    @staticmethod
    def get_instance_or_throw_error() -> MultiFactorAuthRecipe:
        if MultiFactorAuthRecipe.__instance is not None:
            return MultiFactorAuthRecipe.__instance
        raise_general_exception(
            "MultiFactorAuth recipe initialisation not done. Did you forget to call the SuperTokens.init function?"
        )

    @staticmethod
    def reset():
        if ("SUPERTOKENS_ENV" not in environ) or (
            environ["SUPERTOKENS_ENV"] != "testing"
        ):
            raise_general_exception("calling testing function in non testing env")
        MultiFactorAuthRecipe.__instance = None
