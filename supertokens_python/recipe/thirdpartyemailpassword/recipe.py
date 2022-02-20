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
from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.querier import Querier
from supertokens_python.recipe.thirdparty.provider import Provider
from supertokens_python.recipe_module import APIHandled, RecipeModule

from ..emailpassword.utils import (InputResetPasswordUsingTokenFeature,
                                   InputSignUpFeature)
from .api.emailpassword_api_impementation import \
    get_interface_impl as get_email_password_interface_impl
from .api.implementation import APIImplementation
from .api.thirdparty_api_implementation import \
    get_interface_impl as get_third_party_interface_impl
from .recipeimplementation.email_password_recipe_implementation import \
    RecipeImplementation as EmailPasswordRecipeImplementation
from .recipeimplementation.implementation import RecipeImplementation
from .recipeimplementation.third_party_recipe_implementation import \
    RecipeImplementation as ThirdPartyRecipeImplementation
from .utils import InputEmailVerificationConfig

if TYPE_CHECKING:
    from supertokens_python.framework.request import BaseRequest
    from supertokens_python.supertokens import AppInfo

from supertokens_python.exceptions import SuperTokensError
from supertokens_python.recipe.emailpassword import EmailPasswordRecipe
from supertokens_python.recipe.emailpassword.utils import \
    InputOverrideConfig as EPOverrideConfig
from supertokens_python.recipe.emailverification import EmailVerificationRecipe
from supertokens_python.recipe.thirdparty import ThirdPartyRecipe
from supertokens_python.recipe.thirdparty.utils import \
    InputOverrideConfig as TPOverrideConfig
from supertokens_python.recipe.thirdparty.utils import SignInAndUpFeature

from ..emailpassword.interfaces import \
    APIInterface as EmailPasswordAPIInterface
from ..emailpassword.interfaces import \
    RecipeInterface as EmailPasswordRecipeInterface
from ..thirdparty.interfaces import APIInterface as ThirdPartyAPIInterface
from ..thirdparty.interfaces import \
    RecipeInterface as ThirdPartyRecipeInterface
from .exceptions import SupertokensThirdPartyEmailPasswordError
from .interfaces import APIInterface, RecipeInterface
from .utils import InputOverrideConfig, validate_and_normalise_user_input


class ThirdPartyEmailPasswordRecipe(RecipeModule):
    recipe_id = 'thirdpartyemailpassword'
    __instance = None

    def __init__(self, recipe_id: str, app_info: AppInfo,
                 sign_up_feature: Union[InputSignUpFeature, None] = None,
                 reset_password_using_token_feature: Union[InputResetPasswordUsingTokenFeature, None] = None,
                 email_verification_feature: Union[InputEmailVerificationConfig, None] = None,
                 override: Union[InputOverrideConfig, None] = None,
                 providers: Union[List[Provider], None] = None,
                 email_verification_recipe: Union[EmailVerificationRecipe, None] = None,
                 email_password_recipe: Union[EmailPasswordRecipe,
                                              None] = None,
                 third_party_recipe: Union[ThirdPartyRecipe, None] = None):
        super().__init__(recipe_id, app_info)
        self.config = validate_and_normalise_user_input(self,
                                                        sign_up_feature,
                                                        reset_password_using_token_feature,
                                                        email_verification_feature,
                                                        override,
                                                        providers)

        recipe_implementation = RecipeImplementation(Querier.get_instance(EmailPasswordRecipe.recipe_id),
                                                     Querier.get_instance(ThirdPartyRecipe.recipe_id))
        self.recipe_implementation: RecipeInterface = recipe_implementation if self.config.override.functions is None else \
            self.config.override.functions(recipe_implementation)
        api_implementation = APIImplementation()
        self.api_implementation: APIInterface = api_implementation if self.config.override.apis is None else \
            self.config.override.apis(api_implementation)

        if email_verification_recipe is not None:
            self.email_verification_recipe = email_verification_recipe
        else:
            self.email_verification_recipe = EmailVerificationRecipe(recipe_id, app_info,
                                                                     self.config.email_verification_feature)

        def func_override_email_password(_: EmailPasswordRecipeInterface) -> EmailPasswordRecipeInterface:
            return EmailPasswordRecipeImplementation(
                self.recipe_implementation)

        def apis_override_email_password(_: EmailPasswordAPIInterface) -> EmailPasswordAPIInterface:
            return get_email_password_interface_impl(self.api_implementation)

        if email_password_recipe is not None:
            self.email_password_recipe = email_password_recipe
        else:
            self.email_password_recipe = EmailPasswordRecipe(recipe_id, app_info,
                                                             self.config.sign_up_feature,
                                                             self.config.reset_password_using_token_feature,
                                                             None,
                                                             EPOverrideConfig(
                                                                 func_override_email_password,
                                                                 apis_override_email_password
                                                             ),
                                                             self.email_verification_recipe)

        def func_override_third_party(_: ThirdPartyRecipeInterface) -> ThirdPartyRecipeInterface:
            return ThirdPartyRecipeImplementation(self.recipe_implementation)

        def apis_override_third_party(_: ThirdPartyAPIInterface) -> ThirdPartyAPIInterface:
            return get_third_party_interface_impl(self.api_implementation)

        if third_party_recipe is not None:
            self.third_party_recipe: Union[ThirdPartyRecipe, None] = third_party_recipe
        else:
            self.third_party_recipe: Union[ThirdPartyRecipe, None] = None
            if len(self.config.providers) != 0:
                self.third_party_recipe = ThirdPartyRecipe(
                    recipe_id,
                    app_info,
                    SignInAndUpFeature(self.config.providers),
                    None,
                    TPOverrideConfig(
                        func_override_third_party,
                        apis_override_third_party
                    ),
                    self.email_verification_recipe
                )

    def is_error_from_this_recipe_based_on_instance(
            self, err: Exception) -> bool:
        return isinstance(err, SuperTokensError) and (
            isinstance(err, SupertokensThirdPartyEmailPasswordError)
            or
            self.email_verification_recipe.is_error_from_this_recipe_based_on_instance(
                err)
            or
            self.email_password_recipe.is_error_from_this_recipe_based_on_instance(
                err)
            or
            (
                self.third_party_recipe is not None
                and
                self.third_party_recipe.is_error_from_this_recipe_based_on_instance(
                    err)
            )
        )

    def get_apis_handled(self) -> List[APIHandled]:
        apis_handled = self.email_password_recipe.get_apis_handled(
        ) + self.email_verification_recipe.get_apis_handled()
        if self.third_party_recipe is not None:
            apis_handled = apis_handled + self.third_party_recipe.get_apis_handled()
        return apis_handled

    async def handle_api_request(self, request_id: str, request: BaseRequest, path: NormalisedURLPath, method: str,
                                 response: BaseResponse):
        if self.email_password_recipe.return_api_id_if_can_handle_request(
                path, method) is not None:
            return await self.email_password_recipe.handle_api_request(request_id, request, path, method, response)
        if self.third_party_recipe is not None and self.third_party_recipe.return_api_id_if_can_handle_request(path,
                                                                                                               method) is not None:
            return await self.third_party_recipe.handle_api_request(request_id, request, path, method, response)
        return await self.email_verification_recipe.handle_api_request(request_id, request, path, method, response)

    async def handle_error(self, request: BaseRequest, err: SuperTokensError, response: BaseResponse) -> BaseResponse:
        if self.email_password_recipe.is_error_from_this_recipe_based_on_instance(
                err):
            return await self.email_password_recipe.handle_error(
                request, err, response)
        if self.third_party_recipe is not None and self.third_party_recipe.is_error_from_this_recipe_based_on_instance(
                err):
            return await self.third_party_recipe.handle_error(
                request, err, response)
        return await self.email_verification_recipe.handle_error(
            request, err, response)

    def get_all_cors_headers(self) -> List[str]:
        cors_headers = self.email_password_recipe.get_all_cors_headers(
        ) + self.email_verification_recipe.get_all_cors_headers()
        if self.third_party_recipe is not None:
            cors_headers = cors_headers + self.third_party_recipe.get_all_cors_headers()
        return cors_headers

    @staticmethod
    def init(sign_up_feature: Union[InputSignUpFeature, None] = None,
             reset_password_using_token_feature: Union[InputResetPasswordUsingTokenFeature, None] = None,
             email_verification_feature: Union[InputEmailVerificationConfig, None] = None,
             override: Union[InputOverrideConfig, None] = None,
             providers: Union[List[Provider], None] = None):
        def func(app_info: AppInfo):
            if ThirdPartyEmailPasswordRecipe.__instance is None:
                ThirdPartyEmailPasswordRecipe.__instance = ThirdPartyEmailPasswordRecipe(
                    ThirdPartyEmailPasswordRecipe.recipe_id, app_info, sign_up_feature,
                    reset_password_using_token_feature,
                    email_verification_feature,
                    override,
                    providers)
                return ThirdPartyEmailPasswordRecipe.__instance
            raise Exception(None, 'ThirdPartyEmailPassword recipe has already been initialised. Please check your code for bugs.')

        return func

    @staticmethod
    def get_instance() -> ThirdPartyEmailPasswordRecipe:
        if ThirdPartyEmailPasswordRecipe.__instance is not None:
            return ThirdPartyEmailPasswordRecipe.__instance
        raise Exception(
            None,
            'Initialisation not done. Did you forget to call the SuperTokens.init function?')

    @staticmethod
    def reset():
        if ('SUPERTOKENS_ENV' not in environ) or (
                environ['SUPERTOKENS_ENV'] != 'testing'):
            raise Exception(
                None, 'calling testing function in non testing env')
        ThirdPartyEmailPasswordRecipe.__instance = None

    async def get_email_for_user_id(self, user_id: str, user_context: Dict[str, Any]) -> str:
        user_info = await self.recipe_implementation.get_user_by_id(user_id, user_context)
        if user_info is None:
            raise Exception('Unknown User ID provided')
        return user_info.email
