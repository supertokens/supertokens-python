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
from typing import List, TYPE_CHECKING, Union

from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.recipe_module import RecipeModule, APIHandled
from .api.implementation import APIImplementation
from .interfaces import APIOptions
from .recipe_implementation import RecipeImplementation
from supertokens_python.querier import Querier

if TYPE_CHECKING:
    from supertokens_python.framework.request import BaseRequest
    from supertokens_python.framework.response import BaseResponse
    from supertokens_python.supertokens import AppInfo
    from .utils import SignInAndUpFeature, InputOverrideConfig
    from supertokens_python.recipe.emailverification.utils import InputEmailVerificationConfig
from supertokens_python.exceptions import raise_general_exception, SuperTokensError
from supertokens_python.recipe.emailverification import EmailVerificationRecipe
from .utils import validate_and_normalise_user_input
from .api import (
    handle_sign_in_up_api,
    handle_authorisation_url_api,
    handle_apple_redirect_api
)
from .constants import (
    SIGNINUP,
    AUTHORISATIONURL,
    APPLE_REDIRECT_HANDLER
)
from .exceptions import (
    SuperTokensThirdPartyError
)


class ThirdPartyRecipe(RecipeModule):
    recipe_id = 'thirdparty'
    __instance = None

    def __init__(self, recipe_id: str, app_info: AppInfo,
                 sign_in_and_up_feature: SignInAndUpFeature,
                 email_verification_feature: Union[InputEmailVerificationConfig, None] = None,
                 override: Union[InputOverrideConfig, None] = None,
                 email_verification_recipe: Union[EmailVerificationRecipe, None] = None):
        super().__init__(recipe_id, app_info)
        self.config = validate_and_normalise_user_input(self, sign_in_and_up_feature,
                                                        email_verification_feature, override)
        if email_verification_recipe is not None:
            self.email_verification_recipe = email_verification_recipe
        else:
            self.email_verification_recipe = EmailVerificationRecipe(recipe_id, app_info,
                                                                     self.config.email_verification_feature)
        self.providers = self.config.sign_in_and_up_feature.providers
        recipe_implementation = RecipeImplementation(
            Querier.get_instance(recipe_id))
        self.recipe_implementation = recipe_implementation if self.config.override.functions is None else \
            self.config.override.functions(recipe_implementation)
        api_implementation = APIImplementation()
        self.api_implementation = api_implementation if self.config.override.apis is None else \
            self.config.override.apis(api_implementation)

    def is_error_from_this_recipe_based_on_instance(self, err):
        return isinstance(err, SuperTokensError) and (isinstance(err,
                                                                 SuperTokensThirdPartyError) or self.email_verification_recipe.is_error_from_this_recipe_based_on_instance(
            err))

    def get_apis_handled(self) -> List[APIHandled]:
        return [
            APIHandled(NormalisedURLPath(SIGNINUP), 'post', SIGNINUP,
                       self.api_implementation.disable_sign_in_up_post),
            APIHandled(NormalisedURLPath(AUTHORISATIONURL), 'get', AUTHORISATIONURL,
                       self.api_implementation.disable_authorisation_url_get),
            APIHandled(NormalisedURLPath(APPLE_REDIRECT_HANDLER), 'post', APPLE_REDIRECT_HANDLER,
                       self.api_implementation.disable_apple_redirect_handler_post)
        ] + self.email_verification_recipe.get_apis_handled()

    async def handle_api_request(self, request_id: str, request: BaseRequest, path: NormalisedURLPath, method: str,
                                 response: BaseResponse):
        if request_id == SIGNINUP:
            return await handle_sign_in_up_api(self.api_implementation,
                                               APIOptions(request, response, self.recipe_id, self.config,
                                                          self.recipe_implementation, self.providers, self.app_info))
        elif request_id == AUTHORISATIONURL:
            return await handle_authorisation_url_api(self.api_implementation,
                                                      APIOptions(request, response, self.recipe_id, self.config,
                                                                 self.recipe_implementation, self.providers,
                                                                 self.app_info))
        elif request_id == APPLE_REDIRECT_HANDLER:
            return await handle_apple_redirect_api(self.api_implementation,
                                                   APIOptions(request, response, self.recipe_id, self.config,
                                                              self.recipe_implementation, self.providers,
                                                              self.app_info))
        else:
            return await self.email_verification_recipe.handle_api_request(request_id, request, path, method, response)

    async def handle_error(self, request: BaseRequest, error: SuperTokensError, response: BaseResponse):
        if isinstance(error, SuperTokensThirdPartyError):
            raise error
        else:
            return self.email_verification_recipe.handle_error(
                request, error, response)

    def get_all_cors_headers(self) -> List[str]:
        return [] + self.email_verification_recipe.get_all_cors_headers()

    @staticmethod
    def init(sign_in_and_up_feature: SignInAndUpFeature,
             email_verification_feature: Union[InputEmailVerificationConfig, None] = None,
             override: Union[InputOverrideConfig, None] = None):
        def func(app_info: AppInfo):
            if ThirdPartyRecipe.__instance is None:
                ThirdPartyRecipe.__instance = ThirdPartyRecipe(
                    ThirdPartyRecipe.recipe_id, app_info, sign_in_and_up_feature, email_verification_feature, override)
                return ThirdPartyRecipe.__instance
            else:
                raise_general_exception(None, 'ThirdParty recipe has already been initialised. Please check your '
                                              'code for bugs.')

        return func

    @staticmethod
    def get_instance() -> ThirdPartyRecipe:
        if ThirdPartyRecipe.__instance is not None:
            return ThirdPartyRecipe.__instance
        raise_general_exception(
            None,
            'Initialisation not done. Did you forget to call the SuperTokens.init function?')

    @staticmethod
    def reset():
        if ('SUPERTOKENS_ENV' not in environ) or (
                environ['SUPERTOKENS_ENV'] != 'testing'):
            raise_general_exception(
                None, 'calling testing function in non testing env')
        ThirdPartyRecipe.__instance = None

    # instance functions below...............

    async def get_email_for_user_id(self, user_id: str) -> str:
        user_info = await self.recipe_implementation.get_user_by_id(user_id)
        if user_info is None:
            raise Exception('Unknown User ID provided')
        return user_info.email
