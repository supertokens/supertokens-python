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
from typing import TYPE_CHECKING, List, Union, Dict, Any

from supertokens_python.framework.response import BaseResponse
from supertokens_python.ingredients.emaildelivery.types import EmailDeliveryConfig
from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.querier import Querier
from supertokens_python.recipe.emailpassword.types import EmailPasswordIngredients
from supertokens_python.recipe.thirdparty.provider import ProviderInput
from supertokens_python.recipe.thirdparty.types import ThirdPartyIngredients
from supertokens_python.recipe.thirdpartyemailpassword.types import (
    EmailTemplateVars,
    ThirdPartyEmailPasswordIngredients,
)
from supertokens_python.recipe_module import APIHandled, RecipeModule

from ..emailpassword.utils import (
    InputSignUpFeature,
)
from .api.emailpassword_api_impementation import (
    get_interface_impl as get_email_password_interface_impl,
)
from .api.implementation import APIImplementation
from .api.thirdparty_api_implementation import (
    get_interface_impl as get_third_party_interface_impl,
)
from .recipeimplementation.email_password_recipe_implementation import (
    RecipeImplementation as EmailPasswordRecipeImplementation,
)
from .recipeimplementation.implementation import RecipeImplementation
from .recipeimplementation.third_party_recipe_implementation import (
    RecipeImplementation as ThirdPartyRecipeImplementation,
)

if TYPE_CHECKING:
    from supertokens_python.framework.request import BaseRequest
    from supertokens_python.supertokens import AppInfo

from supertokens_python.exceptions import SuperTokensError
from supertokens_python.ingredients.emaildelivery import EmailDeliveryIngredient
from supertokens_python.recipe.emailpassword import EmailPasswordRecipe
from supertokens_python.recipe.emailpassword.utils import (
    InputOverrideConfig as EPOverrideConfig,
)
from supertokens_python.recipe.thirdparty import ThirdPartyRecipe
from supertokens_python.recipe.thirdparty.utils import (
    InputOverrideConfig as TPOverrideConfig,
)
from supertokens_python.recipe.thirdparty.utils import SignInAndUpFeature

from ..emailpassword.interfaces import APIInterface as EmailPasswordAPIInterface
from ..emailpassword.interfaces import RecipeInterface as EmailPasswordRecipeInterface
from ..emailpassword.utils import EmailPasswordConfig
from ..thirdparty.interfaces import APIInterface as ThirdPartyAPIInterface
from ..thirdparty.interfaces import RecipeInterface as ThirdPartyRecipeInterface
from .exceptions import SupertokensThirdPartyEmailPasswordError
from .interfaces import APIInterface, RecipeInterface
from .utils import InputOverrideConfig, validate_and_normalise_user_input


class ThirdPartyEmailPasswordRecipe(RecipeModule):
    recipe_id = "thirdpartyemailpassword"
    __instance = None
    email_delivery: EmailDeliveryIngredient[EmailTemplateVars]

    def __init__(
        self,
        recipe_id: str,
        app_info: AppInfo,
        ingredients: ThirdPartyEmailPasswordIngredients,
        sign_up_feature: Union[InputSignUpFeature, None] = None,
        override: Union[InputOverrideConfig, None] = None,
        providers: Union[List[ProviderInput], None] = None,
        email_password_recipe: Union[EmailPasswordRecipe, None] = None,
        third_party_recipe: Union[ThirdPartyRecipe, None] = None,
        email_delivery: Union[EmailDeliveryConfig[EmailTemplateVars], None] = None,
    ):
        super().__init__(recipe_id, app_info)
        self.config = validate_and_normalise_user_input(
            self,
            sign_up_feature,
            override,
            providers,
            email_delivery,
        )

        def get_emailpassword_config() -> EmailPasswordConfig:
            return self.email_password_recipe.config

        recipe_implementation = RecipeImplementation(
            Querier.get_instance(EmailPasswordRecipe.recipe_id),
            Querier.get_instance(ThirdPartyRecipe.recipe_id),
            self.config.providers,
            get_emailpassword_config,
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

        ep_recipe_implementation = EmailPasswordRecipeImplementation(
            self.recipe_implementation
        )

        email_delivery_ingredient = ingredients.email_delivery
        if email_delivery_ingredient is None:
            self.email_delivery = EmailDeliveryIngredient(
                self.config.get_email_delivery_config(ep_recipe_implementation)
            )
        else:
            self.email_delivery = email_delivery_ingredient

        if email_password_recipe is not None:
            self.email_password_recipe = email_password_recipe
        else:

            def func_override_email_password(_: EmailPasswordRecipeInterface):
                return ep_recipe_implementation

            def apis_override_email_password(_: EmailPasswordAPIInterface):
                return get_email_password_interface_impl(self.api_implementation)

            ingredient = self.email_delivery
            ep_ingredients = EmailPasswordIngredients(ingredient)
            self.email_password_recipe = EmailPasswordRecipe(
                recipe_id,
                app_info,
                ep_ingredients,
                self.config.sign_up_feature,
                EPOverrideConfig(
                    func_override_email_password, apis_override_email_password
                ),
            )

        if third_party_recipe is not None:
            self.third_party_recipe = third_party_recipe
        else:

            def func_override_third_party(
                _: ThirdPartyRecipeInterface,
            ) -> ThirdPartyRecipeInterface:
                return ThirdPartyRecipeImplementation(self.recipe_implementation)

            def apis_override_third_party(
                _: ThirdPartyAPIInterface,
            ) -> ThirdPartyAPIInterface:
                return get_third_party_interface_impl(self.api_implementation)

            # No email delivery ingredient required for third party recipe
            # but we pass an object for future proofing
            tp_ingredients = ThirdPartyIngredients()
            self.third_party_recipe = ThirdPartyRecipe(
                recipe_id,
                app_info,
                SignInAndUpFeature(self.config.providers),
                tp_ingredients,
                TPOverrideConfig(func_override_third_party, apis_override_third_party),
            )

    def is_error_from_this_recipe_based_on_instance(self, err: Exception) -> bool:
        return isinstance(err, SuperTokensError) and (
            isinstance(err, SupertokensThirdPartyEmailPasswordError)
            or self.email_password_recipe.is_error_from_this_recipe_based_on_instance(
                err
            )
            or (
                self.third_party_recipe.is_error_from_this_recipe_based_on_instance(err)
            )
        )

    def get_apis_handled(self) -> List[APIHandled]:
        apis_handled = self.email_password_recipe.get_apis_handled()
        apis_handled += self.third_party_recipe.get_apis_handled()
        return apis_handled

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
        if (
            await self.email_password_recipe.return_api_id_if_can_handle_request(
                path, method, user_context
            )
            is not None
        ):
            return await self.email_password_recipe.handle_api_request(
                request_id, tenant_id, request, path, method, response, user_context
            )
        if (
            await self.third_party_recipe.return_api_id_if_can_handle_request(
                path, method, user_context
            )
            is not None
        ):
            return await self.third_party_recipe.handle_api_request(
                request_id, tenant_id, request, path, method, response, user_context
            )
        return None

    async def handle_error(
        self,
        request: BaseRequest,
        err: SuperTokensError,
        response: BaseResponse,
        user_context: Dict[str, Any],
    ) -> BaseResponse:
        if self.email_password_recipe.is_error_from_this_recipe_based_on_instance(err):
            return await self.email_password_recipe.handle_error(
                request, err, response, user_context
            )
        if self.third_party_recipe.is_error_from_this_recipe_based_on_instance(err):
            return await self.third_party_recipe.handle_error(
                request, err, response, user_context
            )
        raise err

    def get_all_cors_headers(self) -> List[str]:
        cors_headers = self.email_password_recipe.get_all_cors_headers()
        cors_headers += self.third_party_recipe.get_all_cors_headers()
        return cors_headers

    @staticmethod
    def init(
        sign_up_feature: Union[InputSignUpFeature, None] = None,
        override: Union[InputOverrideConfig, None] = None,
        providers: Union[List[ProviderInput], None] = None,
        email_delivery: Union[EmailDeliveryConfig[EmailTemplateVars], None] = None,
    ):
        def func(app_info: AppInfo):
            if ThirdPartyEmailPasswordRecipe.__instance is None:
                ingredients = ThirdPartyEmailPasswordIngredients(None)
                ThirdPartyEmailPasswordRecipe.__instance = (
                    ThirdPartyEmailPasswordRecipe(
                        ThirdPartyEmailPasswordRecipe.recipe_id,
                        app_info,
                        ingredients,
                        sign_up_feature,
                        override,
                        providers,
                        email_delivery=email_delivery,
                    )
                )
                return ThirdPartyEmailPasswordRecipe.__instance
            raise Exception(
                None,
                "ThirdPartyEmailPassword recipe has already been initialised. Please check your code for bugs.",
            )

        return func

    @staticmethod
    def get_instance() -> ThirdPartyEmailPasswordRecipe:
        if ThirdPartyEmailPasswordRecipe.__instance is not None:
            return ThirdPartyEmailPasswordRecipe.__instance
        raise Exception(
            None,
            "Initialisation not done. Did you forget to call the SuperTokens.init function?",
        )

    @staticmethod
    def reset():
        if ("SUPERTOKENS_ENV" not in environ) or (
            environ["SUPERTOKENS_ENV"] != "testing"
        ):
            raise Exception(None, "calling testing function in non testing env")
        ThirdPartyEmailPasswordRecipe.__instance = None
