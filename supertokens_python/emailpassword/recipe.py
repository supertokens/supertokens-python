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

from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.recipe_module import RecipeModule, APIHandled
from typing import List, TYPE_CHECKING
if TYPE_CHECKING:
    from supertokens_python.framework.request import BaseRequest
    from supertokens_python.framework.response import BaseResponse
    from supertokens_python.supertokens import AppInfo
from supertokens_python.exceptions import raise_general_exception, SuperTokensError
from supertokens_python.emailverification import EmailVerificationRecipe
from .utils import validate_and_normalise_user_input
from .api import (
    handle_sign_up_api,
    handle_sign_in_api,
    handle_email_exists_api,
    handle_password_reset_api,
    handle_generate_password_reset_token_api,
    handle_sign_out_api
)
from .constants import (
    SIGNOUT,
    SIGNIN,
    SIGNUP,
    USER_PASSWORD_RESET_TOKEN,
    USER_PASSWORD_RESET,
    SIGNUP_EMAIL_EXISTS
)
from .exceptions import (
    EmailAlreadyExistsError,
    FieldError,
    WrongCredentialsError,
    ResetPasswordInvalidTokenError,
    raise_unknown_user_id_exception
)
from .types import ErrorFormField, User, UsersResponse

from .core_api_calls import (
    sign_in as core_sign_in,
    sign_up as core_sign_up,
    get_user_by_email as core_get_user_by_email,
    get_user_by_id as core_get_user_by_id,
    get_users as core_get_users,
    get_users_count as core_get_users_count,
    create_reset_password_token as core_create_reset_password_token,
    reset_password_using_token as core_reset_password_using_token
)


class EmailPasswordRecipe(RecipeModule):
    recipe_id = 'emailpassword'
    __instance = None

    def __init__(self, recipe_id: str, app_info: AppInfo, config=None, rid_to_core=None):
        super().__init__(recipe_id, app_info, rid_to_core)
        if config is None:
            config = {}
        self.config = validate_and_normalise_user_input(self, app_info, config)
        self.email_verification_recipe = EmailVerificationRecipe(recipe_id, app_info, self.config.email_verification_feature)

    def is_error_from_this_or_child_recipe_based_on_instance(self, err):
        return isinstance(err, SuperTokensError) and (
            err.recipe == self
            or
            self.email_verification_recipe.is_error_from_this_or_child_recipe_based_on_instance(err)
        )

    def get_apis_handled(self) -> List[APIHandled]:
        return [
            APIHandled(NormalisedURLPath(self, SIGNUP), 'post', SIGNUP,
                       self.config.sign_up_feature.disable_default_implementation),
            APIHandled(NormalisedURLPath(self, SIGNIN), 'post', SIGNIN,
                       self.config.sign_in_feature.disable_default_implementation),
            APIHandled(NormalisedURLPath(self, SIGNOUT), 'post', SIGNOUT,
                       self.config.sign_out_feature.disable_default_implementation),
            APIHandled(NormalisedURLPath(self, USER_PASSWORD_RESET_TOKEN), 'post', USER_PASSWORD_RESET_TOKEN,
                       self.config.reset_token_using_password_feature.disable_default_implementation),
            APIHandled(NormalisedURLPath(self, USER_PASSWORD_RESET), 'post', USER_PASSWORD_RESET,
                       self.config.reset_token_using_password_feature.disable_default_implementation),
            APIHandled(NormalisedURLPath(self, SIGNUP_EMAIL_EXISTS), 'post', SIGNUP_EMAIL_EXISTS,
                       self.config.sign_up_feature.disable_default_implementation)

        ] + self.email_verification_recipe.get_apis_handled()

    async def handle_api_request(self, request_id: str, request: BaseRequest, path: NormalisedURLPath, method: str):
        if request_id == SIGNUP:
            return await handle_sign_up_api(self, request)
        elif request_id == SIGNIN:
            return await handle_sign_in_api(self, request)
        elif request_id == SIGNOUT:
            return await handle_sign_out_api(self, request)
        elif request_id == SIGNUP_EMAIL_EXISTS:
            return await handle_email_exists_api(self, request)
        elif request_id == USER_PASSWORD_RESET_TOKEN:
            return await handle_generate_password_reset_token_api(self, request)
        elif request_id == USER_PASSWORD_RESET:
            return await handle_password_reset_api(self, request)
        else:
            return await self.email_verification_recipe.handle_api_request(request_id, request, path, method)

    async def handle_error(self, request: BaseRequest, error: SuperTokensError):
        if isinstance(error, EmailAlreadyExistsError):
            return self.handle_error(request,
                                     FieldError(self, 'Error in input formFields', [ErrorFormField('email', 'This '
                                                                                                            'email '
                                                                                                            'already '
                                                                                                            'exists. '
                                                                                                            'Please '
                                                                                                            'sign in '
                                                                                                            'instead.')
                                                                                    ]
                                                )
                                     )
        elif isinstance(error, WrongCredentialsError):
            return BaseResponse(content={
                'status': 'WRONG_CREDENTIALS_ERROR'
            })
        elif isinstance(error, FieldError):
            return BaseResponse(content={
                'status': 'FIELD_ERROR',
                'formFields': error.get_json_form_fields()
            })
        elif isinstance(error, ResetPasswordInvalidTokenError):
            return BaseResponse(content={
                'status': 'RESET_PASSWORD_INVALID_TOKEN_ERROR'
            })
        else:
            return self.email_verification_recipe.handle_error(request, error)

    def get_all_cors_headers(self) -> List[str]:
        return [] + self.email_verification_recipe.get_all_cors_headers()

    @staticmethod
    def init(config=None):
        def func(app_info: AppInfo):
            if EmailPasswordRecipe.__instance is None:
                EmailPasswordRecipe.__instance = EmailPasswordRecipe(EmailPasswordRecipe.recipe_id, app_info,
                                                                     config)
                return EmailPasswordRecipe.__instance
            else:
                raise_general_exception(None, 'Emailpassword recipe has already been initialised. Please check your '
                                              'code for bugs.')

        return func

    @staticmethod
    def get_instance() -> EmailPasswordRecipe:
        if EmailPasswordRecipe.__instance is not None:
            return EmailPasswordRecipe.__instance
        raise_general_exception(None, 'Initialisation not done. Did you forget to call the SuperTokens.init function?')

    @staticmethod
    def reset():
        if ('SUPERTOKENS_ENV' not in environ) or (
                environ['SUPERTOKENS_ENV'] != 'testing'):
            raise_general_exception(None, 'calling testing function in non testing env')
        EmailPasswordRecipe.__instance = None

    # instance functions below...............

    async def get_email_for_user_id(self, user_id: str) -> str:
        user_info = await self.get_user_by_id(user_id)
        if user_info is None:
            raise_unknown_user_id_exception(self, 'Unknown User ID provided')
        return user_info.email

    async def get_user_by_id(self, user_id: str) -> User:
        return await core_get_user_by_id(self, user_id)

    async def get_user_by_email(self, email: str) -> User:
        return await core_get_user_by_email(self, email)

    async def create_reset_password_token(self, user_id: str) -> str:
        return await core_create_reset_password_token(self, user_id)

    async def reset_password_using_token(self, token: str, new_password: str):
        return await core_reset_password_using_token(self, token, new_password)

    async def sign_in(self, email: str, password: str) -> User:
        return await core_sign_in(self, email, password)

    async def sign_up(self, email: str, password: str) -> User:
        return await core_sign_up(self, email, password)

    async def create_email_verification_token(self, user_id: str) -> str:
        return await self.email_verification_recipe.create_email_verification_token(user_id,
                                                                                    await self.get_email_for_user_id(
                                                                                        user_id))

    async def verify_email_using_token(self, token: str) -> User:
        return await self.email_verification_recipe.verify_email_using_token(token)

    async def is_email_verified(self, user_id: str) -> bool:
        return await self.email_verification_recipe.is_email_verified(user_id,
                                                                      await self.get_email_for_user_id(user_id))

    async def get_users_oldest_first(self, limit: int = None, next_pagination: str = None) -> UsersResponse:
        return await core_get_users(self, 'ASC', limit, next_pagination)

    async def get_users_newest_first(self, limit: int = None, next_pagination: str = None) -> UsersResponse:
        return await core_get_users(self, 'DESC', limit, next_pagination)

    async def get_user_count(self) -> int:
        return await core_get_users_count(self)
