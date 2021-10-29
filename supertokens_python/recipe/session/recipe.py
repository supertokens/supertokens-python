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

from .cookie_and_header import (
    get_cors_allowed_headers,
)
from .exceptions import (
    TokenTheftError,
    UnauthorisedError,
    SuperTokensSessionError,
)
from .api import (
    handle_signout_api,
    handle_refresh_api
)
from os import environ
from typing import List, Union, TYPE_CHECKING
from supertokens_python.framework.response import BaseResponse

if TYPE_CHECKING:
    from supertokens_python.framework import BaseRequest
    from supertokens_python.supertokens import AppInfo
from .utils import validate_and_normalise_user_input
from .constants import SESSION_REFRESH, SIGNOUT
from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.recipe_module import RecipeModule, APIHandled
from supertokens_python.exceptions import raise_general_exception, SuperTokensError
from .recipe_implementation import RecipeImplementation
from supertokens_python.querier import Querier
from .api.implementation import APIImplementation
from .interfaces import APIOptions


class SessionRecipe(RecipeModule):
    recipe_id = 'session'
    __instance = None

    def __init__(self, recipe_id: str, app_info: AppInfo,
                 config=None):
        super().__init__(recipe_id, app_info)
        if config is None:
            config = {}
        self.config = validate_and_normalise_user_input(self, app_info, config)
        recipe_implementation = RecipeImplementation(
            Querier.get_instance(recipe_id), self.config)
        self.recipe_implementation = recipe_implementation if self.config.override.functions is None else self.config.override.functions(
            recipe_implementation)
        api_implementation = APIImplementation()
        self.api_implementation = api_implementation if self.config.override.apis is None else self.config.override.apis(
            api_implementation)

    def is_error_from_this_recipe_based_on_instance(self, err):
        return isinstance(err, SuperTokensError) and isinstance(
            err, SuperTokensSessionError)

    def get_apis_handled(self) -> List[APIHandled]:
        return [
            APIHandled(NormalisedURLPath(SESSION_REFRESH), 'post', SESSION_REFRESH,
                       self.api_implementation.disable_refresh_post),
            APIHandled(NormalisedURLPath(SIGNOUT), 'post', SIGNOUT,
                       self.api_implementation.disable_signout_post)
        ]

    async def handle_api_request(self, request_id: str, request: BaseRequest, _: NormalisedURLPath, __: str,
                                 response: BaseResponse):
        if request_id == SESSION_REFRESH:
            return await handle_refresh_api(self.api_implementation, APIOptions(request, response, self.recipe_id, self.config, self.recipe_implementation))
        else:
            return await handle_signout_api(self.api_implementation, APIOptions(request, response, self.recipe_id, self.config, self.recipe_implementation))

    async def handle_error(self, request: BaseRequest, error: SuperTokensError, response: BaseResponse):
        if isinstance(error, UnauthorisedError):
            return await self.config.error_handlers.on_unauthorised(error.clear_cookies, request, str(error), response)
        elif isinstance(error, TokenTheftError):
            return await self.config.error_handlers.on_token_theft_detected(request, error.session_handle,
                                                                            error.user_id, response)
        else:
            return await self.config.error_handlers.on_try_refresh_token(request, str(error), response)

    def get_all_cors_headers(self) -> List[str]:
        return get_cors_allowed_headers()

    @staticmethod
    def init(config=None):
        def func(app_info: AppInfo):
            if SessionRecipe.__instance is None:
                SessionRecipe.__instance = SessionRecipe(
                    SessionRecipe.recipe_id, app_info, config)
                return SessionRecipe.__instance
            else:
                raise_general_exception(None,
                                        'Session recipe has already been initialised. Please check your code for bugs.')

        return func

    @staticmethod
    def get_instance() -> SessionRecipe:
        if SessionRecipe.__instance is not None:
            return SessionRecipe.__instance
        raise_general_exception(
            None,
            'Initialisation not done. Did you forget to call the SuperTokens.init function?')

    @staticmethod
    def reset():
        if ('SUPERTOKENS_ENV' not in environ) or (
                environ['SUPERTOKENS_ENV'] != 'testing'):
            raise_general_exception(
                None, 'calling testing function in non testing env')
        SessionRecipe.__instance = None

    async def verify_session(self, request: BaseRequest, anti_csrf_check: Union[bool, None] = None, session_required: bool = True):
        return await self.api_implementation.verify_session(APIOptions(request, None, self.recipe_id, self.config, self.recipe_implementation), anti_csrf_check, session_required)
