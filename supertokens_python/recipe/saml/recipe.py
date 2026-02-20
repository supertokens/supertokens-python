# Copyright (c) 2024, VRAI Labs and/or its affiliates. All rights reserved.
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
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Union

from supertokens_python.exceptions import SuperTokensError, raise_general_exception
from supertokens_python.recipe.saml.exceptions import SAMLError
from supertokens_python.recipe_module import APIHandled, RecipeModule

from .interfaces import (
    APIInterface,
    APIOptions,
    RecipeInterface,
)

if TYPE_CHECKING:
    from supertokens_python.framework.request import BaseRequest
    from supertokens_python.framework.response import BaseResponse
    from supertokens_python.supertokens import AppInfo


from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.querier import Querier
from supertokens_python.recipe.saml.api.implementation import (
    APIImplementation,
)

from .api import (
    callback,
    login,
)
from .constants import (
    SAML_CALLBACK_PATH,
    SAML_LOGIN_PATH,
)
from .utils import (
    NormalisedSAMLConfig,
    SAMLConfig,
    SAMLOverrideConfig,
    validate_and_normalise_user_input,
)


class SAMLRecipe(RecipeModule):
    recipe_id = "saml"
    __instance = None

    def __init__(
        self,
        recipe_id: str,
        app_info: AppInfo,
        config: SAMLConfig,
    ) -> None:
        super().__init__(recipe_id, app_info)
        self.config: NormalisedSAMLConfig = validate_and_normalise_user_input(
            config=config,
        )

        from .recipe_implementation import RecipeImplementation

        recipe_implementation: RecipeInterface = RecipeImplementation(
            Querier.get_instance(recipe_id),
        )
        self.recipe_implementation: RecipeInterface = self.config.override.functions(
            recipe_implementation
        )

        api_implementation = APIImplementation()
        self.api_implementation: APIInterface = self.config.override.apis(
            api_implementation
        )

    def is_error_from_this_recipe_based_on_instance(self, err: Exception) -> bool:
        return isinstance(err, SAMLError)

    def get_apis_handled(self) -> List[APIHandled]:
        return [
            APIHandled(
                NormalisedURLPath(SAML_LOGIN_PATH),
                "get",
                SAML_LOGIN_PATH,
                self.api_implementation.disable_login_get,
            ),
            APIHandled(
                NormalisedURLPath(SAML_CALLBACK_PATH),
                "post",
                SAML_CALLBACK_PATH,
                self.api_implementation.disable_callback_post,
            ),
        ]

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
        api_options = APIOptions(
            app_info=self.app_info,
            request=request,
            response=response,
            recipe_id=self.recipe_id,
            config=self.config,
            recipe_implementation=self.recipe_implementation,
        )
        if request_id == SAML_LOGIN_PATH:
            return await login(
                tenant_id, self.api_implementation, api_options, user_context
            )

        if request_id == SAML_CALLBACK_PATH:
            return await callback(
                tenant_id, self.api_implementation, api_options, user_context
            )

        raise Exception(
            "Should never come here: handle_api_request called with unknown id"
        )

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
        override: Optional[SAMLOverrideConfig] = None,
    ):
        from supertokens_python.plugins import OverrideMap, apply_plugins

        config = SAMLConfig(override=override)

        def func(app_info: AppInfo, plugins: List[OverrideMap]) -> SAMLRecipe:
            if SAMLRecipe.__instance is None:
                SAMLRecipe.__instance = SAMLRecipe(
                    recipe_id=SAMLRecipe.recipe_id,
                    app_info=app_info,
                    config=apply_plugins(
                        recipe_id=SAMLRecipe.recipe_id,
                        config=config,
                        plugins=plugins,
                    ),
                )

                return SAMLRecipe.__instance
            raise_general_exception(
                "SAML recipe has already been initialised. Please check your code for bugs."
            )

        return func

    @staticmethod
    def get_instance() -> SAMLRecipe:
        if SAMLRecipe.__instance is not None:
            return SAMLRecipe.__instance
        raise_general_exception(
            "Initialisation not done. Did you forget to call the SuperTokens.init function?"
        )

    @staticmethod
    def get_instance_optional() -> Optional[SAMLRecipe]:
        return SAMLRecipe.__instance

    @staticmethod
    def reset():
        if ("SUPERTOKENS_ENV" not in environ) or (
            environ["SUPERTOKENS_ENV"] != "testing"
        ):
            raise_general_exception("calling testing function in non testing env")
        SAMLRecipe.__instance = None
