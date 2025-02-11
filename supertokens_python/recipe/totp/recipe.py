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
from typing import TYPE_CHECKING, Any, Dict, List, Union

from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.querier import Querier
from supertokens_python.recipe.multifactorauth.types import (
    GetAllAvailableSecondaryFactorIdsFromOtherRecipesFunc,
    GetFactorsSetupForUserFromOtherRecipesFunc,
)
from supertokens_python.recipe.multitenancy.interfaces import TenantConfig
from supertokens_python.recipe_module import APIHandled, RecipeModule
from supertokens_python.types import User

from ...post_init_callbacks import PostSTInitCallbacks
from ..multifactorauth.recipe import MultiFactorAuthRecipe
from .api.implementation import APIImplementation
from .interfaces import APIInterface, RecipeInterface
from .recipe_implementation import RecipeImplementation
from .utils import validate_and_normalise_user_input

if TYPE_CHECKING:
    from supertokens_python.framework.request import BaseRequest
    from supertokens_python.framework.response import BaseResponse
    from supertokens_python.supertokens import AppInfo

from supertokens_python.exceptions import SuperTokensError, raise_general_exception

from .api.create_device import handle_create_device_api
from .api.list_devices import handle_list_devices_api
from .api.remove_device import handle_remove_device_api
from .api.verify_device import handle_verify_device_api
from .api.verify_totp import handle_verify_totp_api
from .constants import (
    CREATE_TOTP_DEVICE,
    LIST_TOTP_DEVICES,
    REMOVE_TOTP_DEVICE,
    VERIFY_TOTP,
    VERIFY_TOTP_DEVICE,
)
from .interfaces import APIOptions
from .types import TOTPConfig


class TOTPRecipe(RecipeModule):
    recipe_id = "totp"
    __instance = None

    def __init__(
        self,
        recipe_id: str,
        app_info: AppInfo,
        config: Union[TOTPConfig, None] = None,
    ):
        super().__init__(recipe_id, app_info)
        self.config = validate_and_normalise_user_input(app_info, config)

        recipe_implementation = RecipeImplementation(
            Querier.get_instance(recipe_id), self.config
        )
        self.recipe_implementation: RecipeInterface = (
            recipe_implementation
            if self.config.override.functions is None
            else self.config.override.functions(recipe_implementation)
        )

        api_implementation = APIImplementation()
        self.api_implementation: APIInterface = (
            api_implementation
            if self.config.override.apis is None
            else self.config.override.apis(api_implementation)
        )

        def callback():
            mfa_instance = MultiFactorAuthRecipe.get_instance()
            if mfa_instance is not None:

                async def f1(_: TenantConfig):
                    return ["totp"]

                async def f2(user: User, user_context: Dict[str, Any]) -> List[str]:
                    device_res = await TOTPRecipe.get_instance_or_throw().recipe_implementation.list_devices(
                        user_id=user.id, user_context=user_context
                    )
                    for device in device_res.devices:
                        if device.verified:
                            return ["totp"]
                    return []

                mfa_instance.add_func_to_get_all_available_secondary_factor_ids_from_other_recipes(
                    GetAllAvailableSecondaryFactorIdsFromOtherRecipesFunc(f1)
                )
                mfa_instance.add_func_to_get_factors_setup_for_user_from_other_recipes(
                    GetFactorsSetupForUserFromOtherRecipesFunc(f2)
                )

        PostSTInitCallbacks.add_post_init_callback(callback)

    def is_error_from_this_recipe_based_on_instance(self, err: Exception) -> bool:
        return False

    def get_apis_handled(self) -> List[APIHandled]:
        return [
            APIHandled(
                NormalisedURLPath(CREATE_TOTP_DEVICE),
                "post",
                CREATE_TOTP_DEVICE,
                self.api_implementation.disable_create_device_post,
            ),
            APIHandled(
                NormalisedURLPath(LIST_TOTP_DEVICES),
                "get",
                LIST_TOTP_DEVICES,
                self.api_implementation.disable_list_devices_get,
            ),
            APIHandled(
                NormalisedURLPath(REMOVE_TOTP_DEVICE),
                "post",
                REMOVE_TOTP_DEVICE,
                self.api_implementation.disable_remove_device_post,
            ),
            APIHandled(
                NormalisedURLPath(VERIFY_TOTP_DEVICE),
                "post",
                VERIFY_TOTP_DEVICE,
                self.api_implementation.disable_verify_device_post,
            ),
            APIHandled(
                NormalisedURLPath(VERIFY_TOTP),
                "post",
                VERIFY_TOTP,
                self.api_implementation.disable_verify_totp_post,
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
    ):
        api_options = APIOptions(
            request,
            response,
            self.recipe_id,
            self.config,
            self.recipe_implementation,
            self.get_app_info(),
            self,
        )
        if request_id == CREATE_TOTP_DEVICE:
            return await handle_create_device_api(
                tenant_id, self.api_implementation, api_options, user_context
            )
        if request_id == LIST_TOTP_DEVICES:
            return await handle_list_devices_api(
                tenant_id, self.api_implementation, api_options, user_context
            )
        if request_id == REMOVE_TOTP_DEVICE:
            return await handle_remove_device_api(
                tenant_id, self.api_implementation, api_options, user_context
            )
        if request_id == VERIFY_TOTP_DEVICE:
            return await handle_verify_device_api(
                tenant_id, self.api_implementation, api_options, user_context
            )
        if request_id == VERIFY_TOTP:
            return await handle_verify_totp_api(
                tenant_id, self.api_implementation, api_options, user_context
            )

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
        config: Union[TOTPConfig, None] = None,
    ):
        def func(app_info: AppInfo):
            if TOTPRecipe.__instance is None:
                TOTPRecipe.__instance = TOTPRecipe(
                    TOTPRecipe.recipe_id,
                    app_info,
                    config,
                )
                return TOTPRecipe.__instance
            raise Exception(
                "TOTP recipe has already been initialised. Please check your code for bugs."
            )

        return func

    @staticmethod
    def get_instance_or_throw() -> TOTPRecipe:
        if TOTPRecipe.__instance is not None:
            return TOTPRecipe.__instance
        raise_general_exception(
            "Initialisation not done. Did you forget to call the SuperTokens.init function?"
        )

    @staticmethod
    def reset():
        if ("SUPERTOKENS_ENV" not in environ) or (
            environ["SUPERTOKENS_ENV"] != "testing"
        ):
            raise_general_exception("calling testing function in non testing env")
        TOTPRecipe.__instance = None
