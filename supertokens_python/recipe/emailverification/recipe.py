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

from supertokens_python.exceptions import (SuperTokensError,
                                           raise_general_exception)
from supertokens_python.recipe.emailverification.exceptions import \
    EmailVerificationInvalidTokenError
from supertokens_python.recipe_module import APIHandled, RecipeModule

from .api.implementation import APIImplementation
from .interfaces import APIOptions
from .recipe_implementation import RecipeImplementation

if TYPE_CHECKING:
    from supertokens_python.framework.request import BaseRequest
    from supertokens_python.framework.response import BaseResponse
    from supertokens_python.supertokens import AppInfo

from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.querier import Querier

from .api import (handle_email_verify_api,
                  handle_generate_email_verify_token_api)
from .constants import USER_EMAIL_VERIFY, USER_EMAIL_VERIFY_TOKEN
from .exceptions import SuperTokensEmailVerificationError
from .utils import (ParentRecipeEmailVerificationConfig,
                    validate_and_normalise_user_input)


class EmailVerificationRecipe(RecipeModule):
    recipe_id = 'emailverification'
    __instance = None

    def __init__(self, recipe_id: str, app_info: AppInfo,
                 config: ParentRecipeEmailVerificationConfig):
        super().__init__(recipe_id, app_info)
        self.config = validate_and_normalise_user_input(app_info, config)
        recipe_implementation = RecipeImplementation(
            Querier.get_instance(recipe_id), self.config)
        self.recipe_implementation = recipe_implementation if self.config.override.functions is None else \
            self.config.override.functions(recipe_implementation)
        api_implementation = APIImplementation()
        self.api_implementation = api_implementation if self.config.override.apis is None else \
            self.config.override.apis(api_implementation)

    def is_error_from_this_recipe_based_on_instance(
            self, err: Exception) -> bool:
        return isinstance(err, SuperTokensError) and isinstance(
            err, SuperTokensEmailVerificationError)

    def get_apis_handled(self) -> List[APIHandled]:
        return [
            APIHandled(NormalisedURLPath(USER_EMAIL_VERIFY_TOKEN), 'post', USER_EMAIL_VERIFY_TOKEN,
                       self.api_implementation.disable_generate_email_verify_token_post),
            APIHandled(NormalisedURLPath(USER_EMAIL_VERIFY), 'post', USER_EMAIL_VERIFY,
                       self.api_implementation.disable_email_verify_post),
            APIHandled(NormalisedURLPath(USER_EMAIL_VERIFY), 'get', USER_EMAIL_VERIFY,
                       self.api_implementation.disable_is_email_verified_get)
        ]

    async def handle_api_request(self, request_id: str, request: BaseRequest, path: NormalisedURLPath, method: str, response: BaseResponse) -> Union[BaseResponse, None]:
        if request_id == USER_EMAIL_VERIFY_TOKEN:
            return await handle_generate_email_verify_token_api(self.api_implementation,
                                                                APIOptions(request, response, self.recipe_id, self.config,
                                                                           self.recipe_implementation))
        return await handle_email_verify_api(self.api_implementation,
                                             APIOptions(request, response, self.recipe_id, self.config,
                                                        self.recipe_implementation))

    async def handle_error(self, request: BaseRequest, err: SuperTokensError, response: BaseResponse) -> BaseResponse:
        if isinstance(err, EmailVerificationInvalidTokenError):
            response.set_json_content(
                {'status': 'EMAIL_VERIFICATION_INVALID_TOKEN_ERROR'})
            return response
        response.set_json_content(
            {'status': 'EMAIL_ALREADY_VERIFIED_ERROR'})
        return response

    def get_all_cors_headers(self) -> List[str]:
        return []

    @staticmethod
    def init(config: ParentRecipeEmailVerificationConfig):
        def func(app_info: AppInfo):
            if EmailVerificationRecipe.__instance is None:
                EmailVerificationRecipe.__instance = EmailVerificationRecipe(EmailVerificationRecipe.recipe_id, app_info, config)
                return EmailVerificationRecipe.__instance
            raise_general_exception('Emailverification recipe has already been initialised. Please check your code for bugs.')

        return func

    @staticmethod
    def get_instance() -> EmailVerificationRecipe:
        if EmailVerificationRecipe.__instance is not None:
            return EmailVerificationRecipe.__instance
        raise_general_exception(
            'Initialisation not done. Did you forget to call the SuperTokens.init function?')

    @staticmethod
    def reset():
        if ('SUPERTOKENS_ENV' not in environ) or (
                environ['SUPERTOKENS_ENV'] != 'testing'):
            raise_general_exception(
                'calling testing function in non testing env')
        EmailVerificationRecipe.__instance = None
