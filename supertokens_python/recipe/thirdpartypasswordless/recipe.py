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
from typing import TYPE_CHECKING, Any, Dict, List, Union

from supertokens_python.framework.response import BaseResponse
from supertokens_python.ingredients.emaildelivery.types import EmailDeliveryConfig
from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.querier import Querier
from supertokens_python.recipe.passwordless.types import PasswordlessIngredients
from supertokens_python.recipe.thirdparty.provider import ProviderInput
from supertokens_python.recipe.thirdparty.types import ThirdPartyIngredients
from supertokens_python.recipe.thirdpartypasswordless.types import (
    ThirdPartyPasswordlessIngredients,
)
from supertokens_python.recipe_module import APIHandled, RecipeModule

from ..passwordless.utils import ContactConfig
from .api.implementation import APIImplementation
from .api.passwordless_api_impementation import (
    get_interface_impl as get_passwordless_interface_impl,
)
from .api.thirdparty_api_implementation import (
    get_interface_impl as get_third_party_interface_impl,
)
from .recipeimplementation.implementation import RecipeImplementation
from .recipeimplementation.passwordless_recipe_implementation import (
    RecipeImplementation as PasswordlessRecipeImplementation,
)
from .recipeimplementation.third_party_recipe_implementation import (
    RecipeImplementation as ThirdPartyRecipeImplementation,
)

if TYPE_CHECKING:
    from supertokens_python.framework.request import BaseRequest
    from supertokens_python.supertokens import AppInfo

from typing import Awaitable, Callable

from supertokens_python.exceptions import SuperTokensError
from supertokens_python.ingredients.emaildelivery import EmailDeliveryIngredient
from supertokens_python.ingredients.smsdelivery import SMSDeliveryIngredient
from supertokens_python.ingredients.smsdelivery.types import SMSDeliveryConfig
from supertokens_python.recipe.thirdparty import ThirdPartyRecipe
from supertokens_python.recipe.thirdparty.utils import (
    InputOverrideConfig as TPOverrideConfig,
)
from supertokens_python.recipe.thirdparty.utils import SignInAndUpFeature
from typing_extensions import Literal

from ..passwordless import PasswordlessRecipe
from ..passwordless.interfaces import APIInterface as PasswordlessAPIInterface
from ..passwordless.interfaces import RecipeInterface as PasswordlessRecipeInterface
from ..passwordless.utils import OverrideConfig as PlessOverrideConfig
from ..thirdparty.interfaces import APIInterface as ThirdPartyAPIInterface
from ..thirdparty.interfaces import RecipeInterface as ThirdPartyRecipeInterface
from .exceptions import SupertokensThirdPartyPasswordlessError
from .interfaces import APIInterface, RecipeInterface
from .types import EmailTemplateVars, SMSTemplateVars
from .utils import InputOverrideConfig, validate_and_normalise_user_input


class ThirdPartyPasswordlessRecipe(RecipeModule):
    recipe_id = "thirdpartypasswordless"
    __instance = None
    email_delivery: EmailDeliveryIngredient[EmailTemplateVars]
    sms_delivery: SMSDeliveryIngredient[SMSTemplateVars]

    def __init__(
        self,
        recipe_id: str,
        app_info: AppInfo,
        contact_config: ContactConfig,
        flow_type: Literal[
            "USER_INPUT_CODE", "MAGIC_LINK", "USER_INPUT_CODE_AND_MAGIC_LINK"
        ],
        ingredients: ThirdPartyPasswordlessIngredients,
        get_custom_user_input_code: Union[
            Callable[[str, Dict[str, Any]], Awaitable[str]], None
        ] = None,
        override: Union[InputOverrideConfig, None] = None,
        providers: Union[List[ProviderInput], None] = None,
        third_party_recipe: Union[ThirdPartyRecipe, None] = None,
        passwordless_recipe: Union[PasswordlessRecipe, None] = None,
        email_delivery: Union[EmailDeliveryConfig[EmailTemplateVars], None] = None,
        sms_delivery: Union[SMSDeliveryConfig[SMSTemplateVars], None] = None,
    ):
        super().__init__(recipe_id, app_info)
        self.config = validate_and_normalise_user_input(
            self,
            contact_config=contact_config,
            flow_type=flow_type,
            get_custom_user_input_code=get_custom_user_input_code,
            override=override,
            providers=providers,
            email_delivery=email_delivery,
            sms_delivery=sms_delivery,
        )

        recipe_implementation = RecipeImplementation(
            Querier.get_instance(PasswordlessRecipe.recipe_id),
            Querier.get_instance(ThirdPartyRecipe.recipe_id),
            self.config.providers,
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

        email_delivery_ingredient = ingredients.email_delivery
        if email_delivery_ingredient is None:
            self.email_delivery = EmailDeliveryIngredient(
                self.config.get_email_delivery_config()
            )
        else:
            self.email_delivery = email_delivery_ingredient

        sms_delivery_ingredient = ingredients.sms_delivery
        if sms_delivery_ingredient is None:
            self.sms_delivery = SMSDeliveryIngredient(
                self.config.get_sms_delivery_config()
            )
        else:
            self.sms_delivery = sms_delivery_ingredient

        if passwordless_recipe is not None:
            self.passwordless_recipe = passwordless_recipe
        else:

            def func_override_passwordless(
                _: PasswordlessRecipeInterface,
            ) -> PasswordlessRecipeInterface:
                return PasswordlessRecipeImplementation(self.recipe_implementation)

            def apis_override_passwordless(
                _: PasswordlessAPIInterface,
            ) -> PasswordlessAPIInterface:
                return get_passwordless_interface_impl(self.api_implementation)

            pless_email_delivery = self.email_delivery
            pless_sms_delivery = self.sms_delivery
            pless_ingredients = PasswordlessIngredients(
                pless_email_delivery, pless_sms_delivery
            )
            self.passwordless_recipe = PasswordlessRecipe(
                recipe_id,
                app_info,
                self.config.contact_config,
                self.config.flow_type,
                pless_ingredients,
                PlessOverrideConfig(
                    func_override_passwordless, apis_override_passwordless
                ),
                self.config.get_custom_user_input_code,
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

            # Thirdparty recipe doesn't need ingredients
            # as of now. But we are passing ingredients object
            # so that it's future-proof.
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
            isinstance(err, SupertokensThirdPartyPasswordlessError)
            or self.passwordless_recipe.is_error_from_this_recipe_based_on_instance(err)
            or (
                self.third_party_recipe.is_error_from_this_recipe_based_on_instance(err)
            )
        )

    def get_apis_handled(self) -> List[APIHandled]:
        apis_handled = self.passwordless_recipe.get_apis_handled()
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
            await self.passwordless_recipe.return_api_id_if_can_handle_request(
                path, method, user_context
            )
            is not None
        ):
            return await self.passwordless_recipe.handle_api_request(
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
        if self.passwordless_recipe.is_error_from_this_recipe_based_on_instance(err):
            return await self.passwordless_recipe.handle_error(
                request, err, response, user_context
            )
        if self.third_party_recipe.is_error_from_this_recipe_based_on_instance(err):
            return await self.third_party_recipe.handle_error(
                request, err, response, user_context
            )
        raise err

    def get_all_cors_headers(self) -> List[str]:
        cors_headers = self.passwordless_recipe.get_all_cors_headers()
        cors_headers += self.third_party_recipe.get_all_cors_headers()
        return cors_headers

    @staticmethod
    def init(
        contact_config: ContactConfig,
        flow_type: Literal[
            "USER_INPUT_CODE", "MAGIC_LINK", "USER_INPUT_CODE_AND_MAGIC_LINK"
        ],
        get_custom_user_input_code: Union[
            Callable[[str, Dict[str, Any]], Awaitable[str]], None
        ] = None,
        email_delivery: Union[EmailDeliveryConfig[EmailTemplateVars], None] = None,
        sms_delivery: Union[SMSDeliveryConfig[SMSTemplateVars], None] = None,
        override: Union[InputOverrideConfig, None] = None,
        providers: Union[List[ProviderInput], None] = None,
    ):
        def func(app_info: AppInfo):
            if ThirdPartyPasswordlessRecipe.__instance is None:
                ingredients = ThirdPartyPasswordlessIngredients(None, None)
                ThirdPartyPasswordlessRecipe.__instance = ThirdPartyPasswordlessRecipe(
                    ThirdPartyPasswordlessRecipe.recipe_id,
                    app_info,
                    contact_config,
                    flow_type,
                    ingredients,
                    get_custom_user_input_code,
                    override,
                    providers,
                    email_delivery=email_delivery,
                    sms_delivery=sms_delivery,
                )
                return ThirdPartyPasswordlessRecipe.__instance
            raise Exception(
                None,
                "ThirdPartyPasswordlessRecipe recipe has already been initialised. Please check your code for bugs.",
            )

        return func

    @staticmethod
    def get_instance() -> ThirdPartyPasswordlessRecipe:
        if ThirdPartyPasswordlessRecipe.__instance is not None:
            return ThirdPartyPasswordlessRecipe.__instance
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
        ThirdPartyPasswordlessRecipe.__instance = None
