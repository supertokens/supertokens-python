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

from ..passwordless.utils import ContactConfig, PhoneOrEmailInput
from .api.implementation import APIImplementation
from .api.passwordless_api_impementation import \
    get_interface_impl as get_passwordless_interface_impl
from .api.thirdparty_api_implementation import \
    get_interface_impl as get_third_party_interface_impl
from .recipeimplementation.implementation import RecipeImplementation
from .recipeimplementation.passwordless_recipe_implementation import \
    RecipeImplementation as PasswordlessRecipeImplementation
from .recipeimplementation.third_party_recipe_implementation import \
    RecipeImplementation as ThirdPartyRecipeImplementation
from .utils import InputEmailVerificationConfig

if TYPE_CHECKING:
    from supertokens_python.framework.request import BaseRequest
    from supertokens_python.supertokens import AppInfo

from typing import Awaitable, Callable

from supertokens_python.exceptions import SuperTokensError
from supertokens_python.recipe.emailverification import EmailVerificationRecipe
from supertokens_python.recipe.thirdparty import ThirdPartyRecipe
from supertokens_python.recipe.thirdparty.utils import \
    InputOverrideConfig as TPOverrideConfig
from supertokens_python.recipe.thirdparty.utils import SignInAndUpFeature
from typing_extensions import Literal

from ..emailverification.interfaces import (
    CreateEmailVerificationTokenEmailAlreadyVerifiedErrorResult,
    CreateEmailVerificationTokenResult)
from ..emailverification.interfaces import RecipeInterface as EVRecipeInterface
from ..emailverification.utils import OverrideConfig as EVOverrideConfig
from ..passwordless import PasswordlessRecipe
from ..passwordless.interfaces import APIInterface as PasswordlessAPIInterface
from ..passwordless.interfaces import \
    RecipeInterface as PasswordlessRecipeInterface
from ..passwordless.utils import OverrideConfig as PlessOverrideConfig
from ..thirdparty.interfaces import APIInterface as ThirdPartyAPIInterface
from ..thirdparty.interfaces import \
    RecipeInterface as ThirdPartyRecipeInterface
from .exceptions import SupertokensThirdPartyPasswordlessError
from .interfaces import APIInterface, RecipeInterface
from .utils import InputOverrideConfig, validate_and_normalise_user_input


class ThirdPartyPasswordlessRecipe(RecipeModule):
    recipe_id = 'thirdpartypasswordless'
    __instance = None

    def __init__(self, recipe_id: str, app_info: AppInfo,
                 contact_config: ContactConfig,
                 flow_type: Literal['USER_INPUT_CODE', 'MAGIC_LINK', 'USER_INPUT_CODE_AND_MAGIC_LINK'],
                 get_link_domain_and_path: Union[Callable[[
                     PhoneOrEmailInput, Dict[str, Any]], Awaitable[str]], None] = None,
                 get_custom_user_input_code: Union[Callable[[Dict[str, Any]], Awaitable[str]], None] = None,
                 email_verification_feature: Union[InputEmailVerificationConfig, None] = None,
                 override: Union[InputOverrideConfig, None] = None,
                 providers: Union[List[Provider], None] = None,
                 email_verification_recipe: Union[EmailVerificationRecipe, None] = None,
                 third_party_recipe: Union[ThirdPartyRecipe, None] = None,
                 passwordless_recipe: Union[PasswordlessRecipe, None] = None):
        super().__init__(recipe_id, app_info)
        self.config = validate_and_normalise_user_input(self,
                                                        contact_config=contact_config,
                                                        email_verification_feature=email_verification_feature,
                                                        flow_type=flow_type,
                                                        get_custom_user_input_code=get_custom_user_input_code,
                                                        get_link_domain_and_path=get_link_domain_and_path,
                                                        override=override,
                                                        providers=providers)

        recipe_implementation = RecipeImplementation(Querier.get_instance(PasswordlessRecipe.recipe_id), Querier.get_instance(ThirdPartyRecipe.recipe_id))
        self.recipe_implementation: RecipeInterface = recipe_implementation if self.config.override.functions is None else \
            self.config.override.functions(recipe_implementation)
        api_implementation = APIImplementation()
        self.api_implementation: APIInterface = api_implementation if self.config.override.apis is None else \
            self.config.override.apis(api_implementation)

        if email_verification_recipe is not None:
            self.email_verification_recipe = email_verification_recipe
        else:
            userProvidedFunctionOverride: Union[None, Callable[[EVRecipeInterface], EVRecipeInterface]] = None
            if self.config.email_verification_feature.override is not None:
                userProvidedFunctionOverride = self.config.email_verification_feature.override.functions

            def email_verification_override(original_impl: EVRecipeInterface) -> EVRecipeInterface:
                og_create_email_verification_token = original_impl.create_email_verification_token
                og_is_email_verified = original_impl.is_email_verified

                async def create_email_verification_token(user_id: str, email: str, user_context: Dict[str, Any]) -> CreateEmailVerificationTokenResult:
                    user = await self.recipe_implementation.get_user_by_id(user_id, user_context)
                    if user is None or user.third_party_info is not None:
                        return await og_create_email_verification_token(user_id, email, user_context)
                    return CreateEmailVerificationTokenEmailAlreadyVerifiedErrorResult()

                async def is_email_verified(user_id: str, email: str, user_context: Dict[str, Any]) -> bool:
                    user = await self.recipe_implementation.get_user_by_id(user_id, user_context)
                    if user is None or user.third_party_info is not None:
                        return await og_is_email_verified(user_id, email, user_context)

                    # this is a passwordless user, so we always want
                    # to return that their info / email is verified
                    return True

                original_impl.create_email_verification_token = create_email_verification_token
                original_impl.is_email_verified = is_email_verified

                if userProvidedFunctionOverride is None:
                    return original_impl
                return userProvidedFunctionOverride(original_impl)

            if self.config.email_verification_feature.override is None:
                self.config.email_verification_feature.override = EVOverrideConfig(email_verification_override)
            else:
                self.config.email_verification_feature.override.functions = email_verification_override
            self.email_verification_recipe = EmailVerificationRecipe(recipe_id, app_info,
                                                                     self.config.email_verification_feature)

        def func_override_passwordless(_: PasswordlessRecipeInterface) -> PasswordlessRecipeInterface:
            return PasswordlessRecipeImplementation(
                self.recipe_implementation)

        def apis_override_passwordless(_: PasswordlessAPIInterface) -> PasswordlessAPIInterface:
            return get_passwordless_interface_impl(self.api_implementation)

        if passwordless_recipe is not None:
            self.passwordless_recipe = passwordless_recipe
        else:
            self.passwordless_recipe = PasswordlessRecipe(recipe_id, app_info,
                                                          self.config.contact_config,
                                                          self.config.flow_type,
                                                          PlessOverrideConfig(
                                                              func_override_passwordless,
                                                              apis_override_passwordless
                                                          ),
                                                          self.config.get_link_domain_and_path,
                                                          self.config.get_custom_user_input_code)

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
            isinstance(err, SupertokensThirdPartyPasswordlessError)
            or
            self.email_verification_recipe.is_error_from_this_recipe_based_on_instance(
                err)
            or
            self.passwordless_recipe.is_error_from_this_recipe_based_on_instance(
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
        apis_handled = self.passwordless_recipe.get_apis_handled(
        ) + self.email_verification_recipe.get_apis_handled()
        if self.third_party_recipe is not None:
            apis_handled = apis_handled + self.third_party_recipe.get_apis_handled()
        return apis_handled

    async def handle_api_request(self, request_id: str, request: BaseRequest, path: NormalisedURLPath, method: str, response: BaseResponse):
        if self.passwordless_recipe.return_api_id_if_can_handle_request(
                path, method) is not None:
            return await self.passwordless_recipe.handle_api_request(request_id, request, path, method, response)
        if self.third_party_recipe is not None and self.third_party_recipe.return_api_id_if_can_handle_request(path,
                                                                                                               method) is not None:
            return await self.third_party_recipe.handle_api_request(request_id, request, path, method, response)
        return await self.email_verification_recipe.handle_api_request(request_id, request, path, method, response)

    async def handle_error(self, request: BaseRequest, err: SuperTokensError, response: BaseResponse) -> BaseResponse:
        if self.passwordless_recipe.is_error_from_this_recipe_based_on_instance(
                err):
            return await self.passwordless_recipe.handle_error(
                request, err, response)
        if self.third_party_recipe is not None and self.third_party_recipe.is_error_from_this_recipe_based_on_instance(
                err):
            return await self.third_party_recipe.handle_error(
                request, err, response)
        return await self.email_verification_recipe.handle_error(
            request, err, response)

    def get_all_cors_headers(self) -> List[str]:
        cors_headers = self.passwordless_recipe.get_all_cors_headers(
        ) + self.email_verification_recipe.get_all_cors_headers()
        if self.third_party_recipe is not None:
            cors_headers = cors_headers + self.third_party_recipe.get_all_cors_headers()
        return cors_headers

    @staticmethod
    def init(contact_config: ContactConfig,
             flow_type: Literal['USER_INPUT_CODE', 'MAGIC_LINK', 'USER_INPUT_CODE_AND_MAGIC_LINK'],
             get_link_domain_and_path: Union[Callable[[
                 PhoneOrEmailInput, Dict[str, Any]], Awaitable[str]], None] = None,
             get_custom_user_input_code: Union[Callable[[Dict[str, Any]], Awaitable[str]], None] = None,
             email_verification_feature: Union[InputEmailVerificationConfig, None] = None,
             override: Union[InputOverrideConfig, None] = None,
             providers: Union[List[Provider], None] = None):
        def func(app_info: AppInfo):
            if ThirdPartyPasswordlessRecipe.__instance is None:
                ThirdPartyPasswordlessRecipe.__instance = ThirdPartyPasswordlessRecipe(
                    ThirdPartyPasswordlessRecipe.recipe_id, app_info, contact_config, flow_type, get_link_domain_and_path, get_custom_user_input_code,
                    email_verification_feature,
                    override,
                    providers)
                return ThirdPartyPasswordlessRecipe.__instance
            raise Exception(None, 'ThirdPartyPasswordlessRecipe recipe has already been initialised. Please check your code for bugs.')

        return func

    @staticmethod
    def get_instance() -> ThirdPartyPasswordlessRecipe:
        if ThirdPartyPasswordlessRecipe.__instance is not None:
            return ThirdPartyPasswordlessRecipe.__instance
        raise Exception(
            None,
            'Initialisation not done. Did you forget to call the SuperTokens.init function?')

    @staticmethod
    def reset():
        if ('SUPERTOKENS_ENV' not in environ) or (
                environ['SUPERTOKENS_ENV'] != 'testing'):
            raise Exception(
                None, 'calling testing function in non testing env')
        ThirdPartyPasswordlessRecipe.__instance = None

    async def get_email_for_user_id(self, user_id: str, user_context: Dict[str, Any]) -> str:
        user_info = await self.recipe_implementation.get_user_by_id(user_id, user_context)
        if user_info is None:
            raise Exception('Unknown User ID provided')
        if user_info.third_party_info is None:
            # this is a passwordless user.. so we always return some random email,
            # and in the function for isEmailVerified, we will check if the user
            # is a passwordless user, and if they are, we will return true in there
            return "_____supertokens_passwordless_user@supertokens.com"
        if user_info.email is None:
            raise Exception("Should never come here")
        return user_info.email
