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
from typing import TYPE_CHECKING, List, Union, Any, Dict

from supertokens_python.querier import Querier

from .api.implementation import APIImplementation
from .api.open_id_discovery_configuration_get import open_id_discovery_configuration_get
from .constants import GET_DISCOVERY_CONFIG_URL
from .exceptions import SuperTokensOpenIdError
from .interfaces import APIOptions
from .recipe_implementation import RecipeImplementation
from .utils import InputOverrideConfig, validate_and_normalise_user_input

if TYPE_CHECKING:
    from supertokens_python.framework.request import BaseRequest
    from supertokens_python.framework.response import BaseResponse
    from supertokens_python.supertokens import AppInfo

from supertokens_python.exceptions import SuperTokensError, raise_general_exception
from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.recipe_module import APIHandled, RecipeModule


class OpenIdRecipe(RecipeModule):
    recipe_id = "openid"
    __instance = None

    def __init__(
        self,
        recipe_id: str,
        app_info: AppInfo,
        jwt_validity_seconds: Union[int, None] = None,
        issuer: Union[str, None] = None,
        override: Union[InputOverrideConfig, None] = None,
    ):
        from supertokens_python.recipe.jwt import JWTRecipe

        super().__init__(recipe_id, app_info)
        self.config = validate_and_normalise_user_input(app_info, issuer, override)
        jwt_feature = None
        if override is not None:
            jwt_feature = override.jwt_feature
        self.jwt_recipe = JWTRecipe(
            recipe_id, app_info, jwt_validity_seconds, jwt_feature
        )

        recipe_implementation = RecipeImplementation(
            Querier.get_instance(recipe_id),
            self.config,
            app_info,
            self.jwt_recipe.recipe_implementation,
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
                path_without_api_base_path=NormalisedURLPath(GET_DISCOVERY_CONFIG_URL),
                request_id=GET_DISCOVERY_CONFIG_URL,
                disabled=self.api_implementation.disable_open_id_discovery_configuration_get,
            )
        ] + self.jwt_recipe.get_apis_handled()

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
        options = APIOptions(
            request,
            response,
            self.get_recipe_id(),
            self.config,
            self.recipe_implementation,
        )

        if request_id == GET_DISCOVERY_CONFIG_URL:
            return await open_id_discovery_configuration_get(
                self.api_implementation, options, user_context
            )
        return await self.jwt_recipe.handle_api_request(
            request_id, tenant_id, request, path, method, response, user_context
        )

    async def handle_error(
        self,
        request: BaseRequest,
        err: SuperTokensError,
        response: BaseResponse,
        user_context: Dict[str, Any],
    ):
        if isinstance(err, SuperTokensOpenIdError):
            raise err
        return await self.jwt_recipe.handle_error(request, err, response, user_context)

    def get_all_cors_headers(self) -> List[str]:
        return self.jwt_recipe.get_all_cors_headers()

    def is_error_from_this_recipe_based_on_instance(self, err: Exception) -> bool:
        return isinstance(err, SuperTokensError) and (
            isinstance(err, SuperTokensOpenIdError)
            or self.jwt_recipe.is_error_from_this_recipe_based_on_instance(err)
        )

    @staticmethod
    def init(
        jwt_validity_seconds: Union[int, None] = None,
        issuer: Union[str, None] = None,
        override: Union[InputOverrideConfig, None] = None,
    ):
        def func(app_info: AppInfo):
            if OpenIdRecipe.__instance is None:
                OpenIdRecipe.__instance = OpenIdRecipe(
                    OpenIdRecipe.recipe_id,
                    app_info,
                    jwt_validity_seconds,
                    issuer,
                    override,
                )
                return OpenIdRecipe.__instance
            raise_general_exception(
                "OpenId recipe has already been initialised. Please check your code for bugs."
            )

        return func

    @staticmethod
    def get_instance() -> OpenIdRecipe:
        if OpenIdRecipe.__instance is not None:
            return OpenIdRecipe.__instance
        raise_general_exception(
            "Initialisation not done. Did you forget to call the SuperTokens.init function?"
        )

    @staticmethod
    def reset():
        if ("SUPERTOKENS_ENV" not in environ) or (
            environ["SUPERTOKENS_ENV"] != "testing"
        ):
            raise_general_exception("calling testing function in non testing env")
        OpenIdRecipe.__instance = None
