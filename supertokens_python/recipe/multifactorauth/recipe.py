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

import importlib
from os import environ
from typing import Any, Dict, List, Optional, Union

from supertokens_python.exceptions import SuperTokensError, raise_general_exception
from supertokens_python.framework import BaseRequest, BaseResponse
from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.post_init_callbacks import PostSTInitCallbacks
from supertokens_python.querier import Querier
from supertokens_python.recipe.multifactorauth.api import (
    resync_session_and_fetch_mfa_info,
)
from supertokens_python.recipe.multifactorauth.constants import (
    RESYNC_SESSION_AND_FETCH_MFA_INFO,
)
from supertokens_python.recipe.multifactorauth.multi_factor_auth_claim import (
    MultiFactorAuthClaim,
)
from supertokens_python.recipe.multitenancy.interfaces import TenantConfig
from supertokens_python.recipe.session.recipe import SessionRecipe
from supertokens_python.recipe_module import APIHandled, RecipeModule
from supertokens_python.supertokens import AppInfo
from supertokens_python.types import RecipeUserId, User

from .interfaces import APIOptions
from .types import (
    GetAllAvailableSecondaryFactorIdsFromOtherRecipesFunc,
    GetEmailsForFactorFromOtherRecipesFunc,
    GetEmailsForFactorOkResult,
    GetEmailsForFactorUnknownSessionRecipeUserIdResult,
    GetFactorsSetupForUserFromOtherRecipesFunc,
    GetPhoneNumbersForFactorsFromOtherRecipesFunc,
    GetPhoneNumbersForFactorsOkResult,
    GetPhoneNumbersForFactorsUnknownSessionRecipeUserIdResult,
    OverrideConfig,
)


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
        self.get_factors_setup_for_user_from_other_recipes_funcs: List[
            GetFactorsSetupForUserFromOtherRecipesFunc
        ] = []
        self.get_all_available_secondary_factor_ids_from_other_recipes_funcs: List[
            GetAllAvailableSecondaryFactorIdsFromOtherRecipesFunc
        ] = []
        self.get_emails_for_factor_from_other_recipes_funcs: List[
            GetEmailsForFactorFromOtherRecipesFunc
        ] = []
        self.get_phone_numbers_for_factor_from_other_recipes_funcs: List[
            GetPhoneNumbersForFactorsFromOtherRecipesFunc
        ] = []
        self.is_get_mfa_requirements_for_auth_overridden: bool = False

        module = importlib.import_module(
            "supertokens_python.recipe.multifactorauth.utils"
        )

        self.config = module.validate_and_normalise_user_input(
            first_factors,
            override,
        )
        from .recipe_implementation import RecipeImplementation

        recipe_implementation = RecipeImplementation(
            Querier.get_instance(recipe_id), self
        )
        self.recipe_implementation = (
            recipe_implementation
            if self.config.override.functions is None
            else self.config.override.functions(recipe_implementation)
        )
        from .api.implementation import APIImplementation

        api_implementation = APIImplementation()
        self.api_implementation = (
            api_implementation
            if self.config.override.apis is None
            else self.config.override.apis(api_implementation)
        )

        def callback():
            from supertokens_python.recipe.multitenancy.recipe import MultitenancyRecipe

            mt_recipe = MultitenancyRecipe.get_instance()
            mt_recipe.static_first_factors = self.config.first_factors

            SessionRecipe.get_instance().add_claim_validator_from_other_recipe(
                MultiFactorAuthClaim.validators.has_completed_mfa_requirements_for_auth()
            )

        PostSTInitCallbacks.add_post_init_callback(callback)

    def is_error_from_this_recipe_based_on_instance(self, err: Exception) -> bool:
        return False

    def get_apis_handled(self) -> List[APIHandled]:
        return [
            APIHandled(
                method="put",
                path_without_api_base_path=NormalisedURLPath(
                    RESYNC_SESSION_AND_FETCH_MFA_INFO
                ),
                request_id=RESYNC_SESSION_AND_FETCH_MFA_INFO,
                disabled=self.api_implementation.disable_resync_session_and_fetch_mfa_info_put,
            )
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
        options = APIOptions(
            request,
            response,
            self.get_recipe_id(),
            self.config,
            self.recipe_implementation,
            self.get_app_info(),
            self,
        )
        return await resync_session_and_fetch_mfa_info.handle_resync_session_and_fetch_mfa_info_api(
            tenant_id, self.api_implementation, options, user_context
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
    def get_instance() -> Optional[MultiFactorAuthRecipe]:
        return MultiFactorAuthRecipe.__instance

    @staticmethod
    def reset():
        if ("SUPERTOKENS_ENV" not in environ) or (
            environ["SUPERTOKENS_ENV"] != "testing"
        ):
            raise_general_exception("calling testing function in non testing env")
        MultiFactorAuthRecipe.__instance = None

    def add_func_to_get_all_available_secondary_factor_ids_from_other_recipes(
        self, func: GetAllAvailableSecondaryFactorIdsFromOtherRecipesFunc
    ):
        self.get_all_available_secondary_factor_ids_from_other_recipes_funcs.append(
            func
        )

    async def get_all_available_secondary_factor_ids(
        self, tenant_config: TenantConfig
    ) -> List[str]:
        factor_ids: List[str] = []
        for (
            func
        ) in self.get_all_available_secondary_factor_ids_from_other_recipes_funcs:
            factor_ids_res = await func.func(tenant_config)
            for factor_id in factor_ids_res:
                if factor_id not in factor_ids:
                    factor_ids.append(factor_id)
        return factor_ids

    def add_func_to_get_factors_setup_for_user_from_other_recipes(
        self, func: GetFactorsSetupForUserFromOtherRecipesFunc
    ):
        self.get_factors_setup_for_user_from_other_recipes_funcs.append(func)

    def add_func_to_get_emails_for_factor_from_other_recipes(
        self, func: GetEmailsForFactorFromOtherRecipesFunc
    ):
        self.get_emails_for_factor_from_other_recipes_funcs.append(func)

    async def get_emails_for_factors(
        self, user: User, session_recipe_user_id: RecipeUserId
    ) -> Union[
        GetEmailsForFactorOkResult,
        GetEmailsForFactorUnknownSessionRecipeUserIdResult,
    ]:
        factorIdToEmailsMap: Dict[str, List[str]] = {}

        for func in self.get_emails_for_factor_from_other_recipes_funcs:
            func_result = await func.func(user, session_recipe_user_id)
            if isinstance(
                func_result, GetEmailsForFactorUnknownSessionRecipeUserIdResult
            ):
                return GetEmailsForFactorUnknownSessionRecipeUserIdResult()
            factorIdToEmailsMap.update(func_result.factor_id_to_emails_map)

        return GetEmailsForFactorOkResult(factor_id_to_emails_map=factorIdToEmailsMap)

    def add_func_to_get_phone_numbers_for_factors_from_other_recipes(
        self, func: GetPhoneNumbersForFactorsFromOtherRecipesFunc
    ):
        self.get_phone_numbers_for_factor_from_other_recipes_funcs.append(func)

    async def get_phone_numbers_for_factors(
        self, user: User, session_recipe_user_id: RecipeUserId
    ) -> Union[
        GetPhoneNumbersForFactorsOkResult,
        GetPhoneNumbersForFactorsUnknownSessionRecipeUserIdResult,
    ]:
        factorIdToPhoneNumberMap: Dict[str, List[str]] = {}

        for func in self.get_phone_numbers_for_factor_from_other_recipes_funcs:
            func_result = await func.func(user, session_recipe_user_id)
            if isinstance(
                func_result, GetPhoneNumbersForFactorsUnknownSessionRecipeUserIdResult
            ):
                return GetPhoneNumbersForFactorsUnknownSessionRecipeUserIdResult()
            factorIdToPhoneNumberMap.update(func_result.factor_id_to_phone_number_map)

        return GetPhoneNumbersForFactorsOkResult(
            factor_id_to_phone_number_map=factorIdToPhoneNumberMap
        )
