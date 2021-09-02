"""
Copyright (c) 2021, VRAI Labs and/or its affiliates. All rights reserved.

This software is licensed under the Apache License, Version 2.0 (the
"License") as published by the Apache Software Foundation.

You may not use this file except in compliance with the License. You may
obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.
"""
from __future__ import annotations
from os import environ

from supertokens_python.exceptions import raise_general_exception, SuperTokensError
from supertokens_python.recipe_module import RecipeModule, APIHandled
from typing import List, TYPE_CHECKING
if TYPE_CHECKING:
    from supertokens_python.framework.request import BaseRequest
    from supertokens_python.framework.response import BaseResponse
    from supertokens_python.supertokens import AppInfo
    from .types import User
from supertokens_python.normalised_url_path import NormalisedURLPath
from .utils import validate_and_normalise_user_input
from .api import (
    handle_generate_email_verify_token_api,
    handle_email_verify_api
)
from .core_api_calls import (
    create_email_verification_token as core_create_email_verification_token,
    is_email_verified as core_is_email_verified,
    verify_email_using_token as core_verify_email_using_token
)
from .constants import (
    USER_EMAIL_VERIFY,
    USER_EMAIL_VERIFY_TOKEN
)
from .exceptions import (
    EmailVerificationInvalidTokenError
)


class EmailVerificationRecipe(RecipeModule):
    recipe_id = 'emailverification'
    __instance = None

    def __init__(self, recipe_id: str, app_info: AppInfo, config, rid_to_core=None):
        super().__init__(recipe_id, app_info, rid_to_core)
        self.config = validate_and_normalise_user_input(app_info, config)

    def is_error_from_this_or_child_recipe_based_on_instance(self, err):
        return isinstance(err, SuperTokensError) and err.recipe == self

    def get_apis_handled(self) -> List[APIHandled]:
        return [
            APIHandled(NormalisedURLPath(self, USER_EMAIL_VERIFY_TOKEN), 'post', USER_EMAIL_VERIFY_TOKEN,
                       self.config.disable_default_implementation),
            APIHandled(NormalisedURLPath(self, USER_EMAIL_VERIFY), 'post', USER_EMAIL_VERIFY,
                       self.config.disable_default_implementation),
            APIHandled(NormalisedURLPath(self, USER_EMAIL_VERIFY), 'get', USER_EMAIL_VERIFY,
                       self.config.disable_default_implementation)
        ]

    async def handle_api_request(self, request_id: str, request: BaseRequest, _: NormalisedURLPath, __: str):
        if request_id == USER_EMAIL_VERIFY_TOKEN:
            return await handle_generate_email_verify_token_api(self, request)
        else:
            return await handle_email_verify_api(self, request)

    async def handle_error(self, request: BaseRequest, error: SuperTokensError):
        if isinstance(error, EmailVerificationInvalidTokenError):
            return BaseResponse(content={'status': 'EMAIL_VERIFICATION_INVALID_TOKEN_ERROR'})
        else:
            return BaseResponse(content={'status': 'EMAIL_ALREADY_VERIFIED_ERROR'})

    def get_all_cors_headers(self) -> List[str]:
        return []

    @staticmethod
    def init(config=None):
        def func(app_info: AppInfo):
            if EmailVerificationRecipe.__instance is None:
                EmailVerificationRecipe.__instance = EmailVerificationRecipe(EmailVerificationRecipe.recipe_id, app_info, config)
                return EmailVerificationRecipe.__instance
            else:
                raise_general_exception(None, 'Emailverification recipe has already been initialised. Please check '
                                              'your code for bugs.')
        return func

    @staticmethod
    def get_instance() -> EmailVerificationRecipe:
        if EmailVerificationRecipe.__instance is not None:
            return EmailVerificationRecipe.__instance
        raise_general_exception(None, 'Initialisation not done. Did you forget to call the SuperTokens.init function?')

    @staticmethod
    def reset():
        if ('SUPERTOKENS_ENV' not in environ) or (
                environ['SUPERTOKENS_ENV'] != 'testing'):
            raise_general_exception(None, 'calling testing function in non testing env')
        EmailVerificationRecipe.__instance = None

    # instance functions below...............

    async def create_email_verification_token(self, user_id: str, email: str) -> str:
        return await core_create_email_verification_token(self, user_id, email)

    async def verify_email_using_token(self, token: str) -> User:
        return await core_verify_email_using_token(self, token)

    async def is_email_verified(self, user_id: str, email: str) -> bool:
        return await core_is_email_verified(self, user_id, email)
