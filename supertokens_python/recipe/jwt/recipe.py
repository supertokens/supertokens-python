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
from typing import TYPE_CHECKING, List, Union

from supertokens_python.querier import Querier
from supertokens_python.recipe.jwt.api.implementation import APIImplementation
from supertokens_python.recipe.jwt.api.jwks_get import jwks_get
from supertokens_python.recipe.jwt.constants import GET_JWKS_API
from supertokens_python.recipe.jwt.exceptions import SuperTokensJWTError
from supertokens_python.recipe.jwt.interfaces import APIOptions
from supertokens_python.recipe.jwt.recipe_implementation import RecipeImplementation
from supertokens_python.recipe.jwt.utils import (
    OverrideConfig,
    validate_and_normalise_user_input,
)

if TYPE_CHECKING:
    from supertokens_python.framework.request import BaseRequest
    from supertokens_python.framework.response import BaseResponse
    from supertokens_python.supertokens import AppInfo

from supertokens_python.exceptions import SuperTokensError, raise_general_exception
from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.recipe_module import APIHandled, RecipeModule


class JWTRecipe(RecipeModule):
    recipe_id = "jwt"
    __instance = None

    def __init__(
        self,
        recipe_id: str,
        app_info: AppInfo,
        jwt_validity_seconds: Union[int, None] = None,
        override: Union[OverrideConfig, None] = None,
    ):
        super().__init__(recipe_id, app_info)
        self.config = validate_and_normalise_user_input(jwt_validity_seconds, override)

        recipe_implementation = RecipeImplementation(
            Querier.get_instance(recipe_id), self.config, app_info
        )
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

    def get_apis_handled(self) -> List[APIHandled]:
        return [
            APIHandled(
                method="get",
                path_without_api_base_path=NormalisedURLPath(GET_JWKS_API),
                request_id=GET_JWKS_API,
                disabled=self.api_implementation.disable_jwks_get,
            )
        ]

    async def handle_api_request(
        self,
        request_id: str,
        request: BaseRequest,
        path: NormalisedURLPath,
        method: str,
        response: BaseResponse,
    ):
        options = APIOptions(
            request,
            response,
            self.get_recipe_id(),
            self.config,
            self.recipe_implementation,
        )

        return await jwks_get(self.api_implementation, options)

    async def handle_error(
        self, request: BaseRequest, err: SuperTokensError, response: BaseResponse
    ):
        raise err

    def get_all_cors_headers(self) -> List[str]:
        return []

    def is_error_from_this_recipe_based_on_instance(self, err: Exception) -> bool:
        return isinstance(err, SuperTokensError) and isinstance(
            err, SuperTokensJWTError
        )

    @staticmethod
    def init(
        jwt_validity_seconds: Union[int, None] = None,
        override: Union[OverrideConfig, None] = None,
    ):
        def func(app_info: AppInfo):
            if JWTRecipe.__instance is None:
                JWTRecipe.__instance = JWTRecipe(
                    JWTRecipe.recipe_id, app_info, jwt_validity_seconds, override
                )
                return JWTRecipe.__instance
            raise_general_exception(
                "JWT recipe has already been initialised. Please check "
                "your code for bugs."
            )

        return func

    @staticmethod
    def get_instance() -> JWTRecipe:
        if JWTRecipe.__instance is not None:
            return JWTRecipe.__instance
        raise_general_exception(
            "Initialisation not done. Did you forget to call the SuperTokens.init function?"
        )

    @staticmethod
    def reset():
        if ("SUPERTOKENS_ENV" not in environ) or (
            environ["SUPERTOKENS_ENV"] != "testing"
        ):
            raise_general_exception("calling testing function in non testing env")
        JWTRecipe.__instance = None
