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
from typing import List, TYPE_CHECKING, Union

from ..framework.response import BaseResponse

if TYPE_CHECKING:
    from supertokens_python.framework.request import BaseRequest
    from supertokens_python.supertokens import AppInfo
from supertokens_python.exceptions import raise_general_exception, SuperTokensError
from supertokens_python.emailverification import EmailVerificationRecipe
from supertokens_python.emailpassword import EmailPasswordRecipe
from supertokens_python.thirdparty import ThirdPartyRecipe
from .utils import (
    validate_and_normalise_user_input,
    extract_pagination_token,
    combine_pagination_results
)
from .exceptions import (
    raise_unknown_user_id_exception
)
from .types import (
    SignInUpResponse, User, UsersResponse,
    EmailPasswordSessionDataAndJWTContext,
    EmailPasswordSignInContext,
    EmailPasswordSignUpContext,
    ThirdPartyContext,
    NextPaginationToken
)


class ThirdPartyEmailPasswordRecipe(RecipeModule):
    recipe_id = 'thirdpartyemailpassword'
    __instance = None

    def __init__(self, recipe_id: str, app_info: AppInfo, config=None):
        super().__init__(recipe_id, app_info)
        if config is None:
            config = {}
        self.config = validate_and_normalise_user_input(self, config)

        async def email_password_recipe_session_feature_set_jwt_payload(user, form_fields, action):
            return await self.config.session_feature.set_jwt_payload(user, EmailPasswordSessionDataAndJWTContext(form_fields), action)

        async def email_password_recipe_session_feature_set_session_data(user, form_fields, action):
            return await self.config.session_feature.set_session_data(user, EmailPasswordSessionDataAndJWTContext(form_fields), action)

        async def email_password_recipe_sign_up_feature_handle_post_sign_up(user, form_fields):
            return await self.config.sign_up_feature.handle_post_sign_up(user, EmailPasswordSignUpContext(form_fields))

        async def email_password_recipe_sign_in_feature_handle_post_sign_in(user):
            return await self.config.sign_in_feature.handle_post_sign_in(user, EmailPasswordSignInContext())

        async def third_party_recipe_session_feature_set_jwt_payload(user, form_fields, action):
            return await self.config.session_feature.set_jwt_payload(user, ThirdPartyContext(form_fields), action)

        async def third_party_recipe_session_feature_set_session_data(user, form_fields, action):
            return await self.config.session_feature.set_session_data(user, ThirdPartyContext(form_fields), action)

        async def third_party_recipe_sign_in_feature_handle_post_sign_up_in(user, third_party_auth_code_response, is_new_user):
            if is_new_user:
                return await self.config.sign_up_feature.handle_post_sign_up(user, ThirdPartyContext(
                    third_party_auth_code_response))
            else:
                return await self.config.sign_in_feature.handle_post_sign_in(user, ThirdPartyContext(
                    third_party_auth_code_response))

        self.email_password_recipe = EmailPasswordRecipe(recipe_id, app_info, {
            'session_feature': {
                'set_jwt_payload': email_password_recipe_session_feature_set_jwt_payload,
                'set_session_data': email_password_recipe_session_feature_set_session_data
            },
            'sign_up_feature': {
                'disable_default_implementation': self.config.sign_up_feature.disable_default_implementation,
                'form_fields': self.config.sign_up_feature.form_fields,
                'handle_post_sign_up': email_password_recipe_sign_up_feature_handle_post_sign_up
            },
            'sign_in_feature': {
                'disable_default_implementation': self.config.sign_in_feature.disable_default_implementation,
                'handle_post_sign_in': email_password_recipe_sign_in_feature_handle_post_sign_in
            },
            'sign_out_feature': {
                'disable_default_implementation': self.config.sign_out_feature.disable_default_implementation,
            },
            'reset_password_using_token_feature': self.config.reset_password_using_token_feature,
            'email_verification_feature': {
                'disable_default_implementation': True
            }
        }, EmailPasswordRecipe.recipe_id)
        self.third_party_recipe: Union[ThirdPartyRecipe, None] = None
        if len(self.config.providers) != 0:
            self.third_party_recipe = ThirdPartyRecipe(recipe_id, app_info, {
                'session_feature': {
                    'set_jwt_payload': third_party_recipe_session_feature_set_jwt_payload,
                    'set_session_data': third_party_recipe_session_feature_set_session_data
                },
                'sign_in_and_up_feature': {
                    'disable_default_implementation': self.config.sign_in_feature.disable_default_implementation or self.config.sign_up_feature.disable_default_implementation,
                    'handle_post_sign_up_in': third_party_recipe_sign_in_feature_handle_post_sign_up_in,
                    'providers': self.config.providers
                },
                'sign_out_feature': {
                    'disable_default_implementation': True
                },
                'email_verification_feature': {
                    'disable_default_implementation': True
                }
            }, ThirdPartyRecipe.recipe_id)
        self.email_verification_recipe = EmailVerificationRecipe(recipe_id, app_info,
                                                                 self.config.email_verification_feature)

    def is_error_from_this_or_child_recipe_based_on_instance(self, err):
        return isinstance(err, SuperTokensError) and (
            err.recipe == self
            or
            self.email_verification_recipe.is_error_from_this_or_child_recipe_based_on_instance(err)
            or
            self.email_password_recipe.is_error_from_this_or_child_recipe_based_on_instance(err)
            or
            (
                self.third_party_recipe is not None
                and
                self.third_party_recipe.is_error_from_this_or_child_recipe_based_on_instance(err)
            )
        )

    def get_apis_handled(self) -> List[APIHandled]:
        apis_handled = self.email_password_recipe.get_apis_handled() + self.email_verification_recipe.get_apis_handled()
        if self.third_party_recipe is not None:
            apis_handled = apis_handled + self.third_party_recipe.get_apis_handled()
        return apis_handled

    async def handle_api_request(self, request_id: str, request: BaseRequest, path: NormalisedURLPath, method: str, response: BaseResponse):
        if self.email_password_recipe.return_api_id_if_can_handle_request(path, method) is not None:
            return await self.email_password_recipe.handle_api_request(request_id, request, path, method, response)
        elif self.third_party_recipe is not None and self.third_party_recipe.return_api_id_if_can_handle_request(path, method) is not None:
            return await self.third_party_recipe.handle_api_request(request_id, request, path, method, response)
        else:
            return await self.email_verification_recipe.handle_api_request(request_id, request, path, method, response)

    async def handle_error(self, request: BaseRequest, error: SuperTokensError, response: BaseResponse):
        if self.email_password_recipe.is_error_from_this_or_child_recipe_based_on_instance(error):
            return self.email_password_recipe.handle_error(request, error, response)
        if self.third_party_recipe is not None and self.third_party_recipe.is_error_from_this_or_child_recipe_based_on_instance(error):
            return self.third_party_recipe.handle_error(request, error, response)
        else:
            return self.email_verification_recipe.handle_error(request, error, response)

    def get_all_cors_headers(self) -> List[str]:
        cors_headers = self.email_password_recipe.get_all_cors_headers() + self.email_verification_recipe.get_all_cors_headers()
        if self.third_party_recipe is not None:
            cors_headers = cors_headers + self.third_party_recipe.get_all_cors_headers()
        return cors_headers

    @staticmethod
    def init(config=None):
        def func(app_info: AppInfo):
            if ThirdPartyEmailPasswordRecipe.__instance is None:
                ThirdPartyEmailPasswordRecipe.__instance = ThirdPartyEmailPasswordRecipe(ThirdPartyEmailPasswordRecipe.recipe_id, app_info, config)
                return ThirdPartyEmailPasswordRecipe.__instance
            else:
                raise_general_exception(None, 'ThirdPartyEmailPassword recipe has already been initialised. Please '
                                              'check your code for bugs.')

        return func

    @staticmethod
    def get_instance() -> ThirdPartyEmailPasswordRecipe:
        if ThirdPartyEmailPasswordRecipe.__instance is not None:
            return ThirdPartyEmailPasswordRecipe.__instance
        raise_general_exception(None, 'Initialisation not done. Did you forget to call the SuperTokens.init function?')

    @staticmethod
    def reset():
        if ('SUPERTOKENS_ENV' not in environ) or (
                environ['SUPERTOKENS_ENV'] != 'testing'):
            raise_general_exception(None, 'calling testing function in non testing env')
        ThirdPartyRecipe.__instance = None

    # instance functions below...............

    async def get_email_for_user_id(self, user_id: str) -> str:
        user_info = await self.get_user_by_id(user_id)
        if user_info is None:
            raise_unknown_user_id_exception(self, 'Unknown User ID provided')
        return user_info.email

    async def get_user_by_id(self, user_id: str) -> Union[User, None]:
        user = await self.email_password_recipe.get_user_by_id(user_id)
        if user is not None:
            return user
        if self.third_party_recipe is None:
            return None
        return await self.third_party_recipe.get_user_by_id(user_id)

    async def get_user_by_email(self, email: str) -> Union[User, None]:
        return await self.email_password_recipe.get_user_by_email(email)

    async def get_user_by_third_party_info(self, third_party_id: str, third_party_user_id: str) -> Union[User, None]:
        if self.third_party_recipe is None:
            return None
        return await self.third_party_recipe.get_user_by_third_party_info(third_party_id, third_party_user_id)

    async def sign_in(self, email: str, password: str) -> User:
        return await self.email_password_recipe.sign_in(email, password)

    async def sign_up(self, email: str, password: str) -> User:
        return await self.email_password_recipe.sign_up(email, password)

    async def sign_in_up(self, third_party_id: str, third_party_user_id: str, email: str,
                         email_verified: bool) -> SignInUpResponse:
        if self.third_party_recipe is None:
            raise_general_exception(self, 'No thirdparty provider configured')
        return await self.third_party_recipe.sign_in_up(third_party_id, third_party_user_id, email, email_verified)

    async def create_email_verification_token(self, user_id: str) -> str:
        return await self.email_verification_recipe.create_email_verification_token(user_id,
                                                                                    await self.get_email_for_user_id(
                                                                                        user_id))

    async def verify_email_using_token(self, token: str) -> User:
        return await self.email_verification_recipe.verify_email_using_token(token)

    async def is_email_verified(self, user_id: str) -> bool:
        return await self.email_verification_recipe.is_email_verified(user_id,
                                                                      await self.get_email_for_user_id(user_id))

    async def create_reset_password_token(self, user_id: str) -> str:
        return await self.email_password_recipe.create_reset_password_token(user_id)

    async def reset_password_using_token(self, token: str, new_password: str):
        return await self.email_password_recipe.reset_password_using_token(token, new_password)

    async def get_users_oldest_first(self, limit: int = None, next_pagination: str = None) -> UsersResponse:
        if limit is None:
            limit = 100
        next_pagination_tokens = NextPaginationToken('null', 'null')
        if next_pagination is not None:
            next_pagination_tokens = extract_pagination_token(self, next_pagination)
        email_password_result_promise = self.email_password_recipe.get_users_oldest_first(limit, next_pagination_tokens.email_password_pagination_token)
        third_party_result = UsersResponse([], None) if self.third_party_recipe is None else await self.third_party_recipe.get_users_oldest_first(limit, next_pagination_tokens.third_party_pagination_token)
        email_password_result = await email_password_result_promise
        return combine_pagination_results(third_party_result, email_password_result, limit, True)

    async def get_users_newest_first(self, limit: int = None, next_pagination: str = None) -> UsersResponse:
        if limit is None:
            limit = 100
        next_pagination_tokens = NextPaginationToken('null', 'null')
        if next_pagination is not None:
            next_pagination_tokens = extract_pagination_token(self, next_pagination)
        email_password_result_promise = self.email_password_recipe.get_users_newest_first(limit, next_pagination_tokens.email_password_pagination_token)
        third_party_result = UsersResponse([], None) if self.third_party_recipe is None else await self.third_party_recipe.get_users_newest_first(
            limit, next_pagination_tokens.third_party_pagination_token)
        email_password_result = await email_password_result_promise
        return combine_pagination_results(third_party_result, email_password_result, limit, False)

    async def get_user_count(self) -> int:
        promise1 = self.email_password_recipe.get_user_count()
        count2 = await self.third_party_recipe.get_user_count() if self.third_party_recipe is not None else 0
        return await promise1 + count2
