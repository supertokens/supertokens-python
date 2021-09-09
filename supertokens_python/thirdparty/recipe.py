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

if TYPE_CHECKING:
    from supertokens_python.framework.request import BaseRequest
    from supertokens_python.framework.response import BaseResponse
    from supertokens_python.supertokens import AppInfo
from supertokens_python.exceptions import raise_general_exception, SuperTokensError
from supertokens_python.emailverification import EmailVerificationRecipe
from .utils import validate_and_normalise_user_input
from .api import (
    handle_sign_in_up_api,
    handle_authorisation_url_api,
    handle_sign_out_api
)
from .constants import (
    SIGNOUT,
    SIGNINUP,
    AUTHORISATIONURL
)
from .exceptions import (
    NoEmailGivenByProviderError,
    raise_unknown_user_id_exception
)
from .types import SignInUpResponse, User, UsersResponse
from .core_api_calls import (
    sign_in_up as core_sign_in_up,
    get_user_by_id as core_get_user_by_id,
    get_users as core_get_users,
    get_users_count as core_get_users_count,
    get_user_by_third_party_info as core_get_user_by_third_party_info
)


class ThirdPartyRecipe(RecipeModule):
    recipe_id = 'thirdparty'
    __instance = None

    def __init__(self, recipe_id: str, app_info: AppInfo, config=None, rid_to_core=None):
        super().__init__(recipe_id, app_info, rid_to_core)
        if config is None:
            config = {}
        self.config = validate_and_normalise_user_input(self, config)
        self.email_verification_recipe = EmailVerificationRecipe(recipe_id, app_info,
                                                                 self.config.email_verification_feature)
        self.providers = self.config.sign_in_and_up_feature.providers

    def is_error_from_this_or_child_recipe_based_on_instance(self, err):
        return isinstance(err, SuperTokensError) and (
            err.recipe == self
            or
            self.email_verification_recipe.is_error_from_this_or_child_recipe_based_on_instance(err)
        )

    def get_apis_handled(self) -> List[APIHandled]:
        return [
            APIHandled(NormalisedURLPath(self, SIGNINUP), 'post', SIGNINUP,
                       self.config.sign_in_and_up_feature.disable_default_implementation),
            APIHandled(NormalisedURLPath(self, SIGNOUT), 'post', SIGNOUT,
                       self.config.sign_out_feature.disable_default_implementation),
            APIHandled(NormalisedURLPath(self, AUTHORISATIONURL), 'get', AUTHORISATIONURL,
                       self.config.sign_in_and_up_feature.disable_default_implementation)
        ] + self.email_verification_recipe.get_apis_handled()

    async def handle_api_request(self, request_id: str, request: BaseRequest, path: NormalisedURLPath, method: str, response: BaseResponse):
        if request_id == SIGNINUP:
            return await handle_sign_in_up_api(self, request, response)
        elif request_id == SIGNOUT:
            return await handle_sign_out_api(self, request, response)
        elif request_id == AUTHORISATIONURL:
            return await handle_authorisation_url_api(self, request, response)
        else:
            return await self.email_verification_recipe.handle_api_request(request_id, request, path, method, response)

    async def handle_error(self, request: BaseRequest, error: SuperTokensError, response: BaseResponse):
        if isinstance(error, NoEmailGivenByProviderError):
            response.set_content({
                'status': 'NO_EMAIL_GIVEN_BY_PROVIDER'
            })

            return response

        else:
            return self.email_verification_recipe.handle_error(request, error, response)

    def get_all_cors_headers(self) -> List[str]:
        return [] + self.email_verification_recipe.get_all_cors_headers()

    @staticmethod
    def init(config=None):
        def func(app_info: AppInfo):
            if ThirdPartyRecipe.__instance is None:
                ThirdPartyRecipe.__instance = ThirdPartyRecipe(ThirdPartyRecipe.recipe_id, app_info, config)
                return ThirdPartyRecipe.__instance
            else:
                raise_general_exception(None, 'ThirdParty recipe has already been initialised. Please check your '
                                              'code for bugs.')

        return func

    @staticmethod
    def get_instance() -> ThirdPartyRecipe:
        if ThirdPartyRecipe.__instance is not None:
            return ThirdPartyRecipe.__instance
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
        return await core_get_user_by_id(self, user_id)

    async def get_user_by_third_party_info(self, third_party_id: str, third_party_user_id: str) -> Union[User, None]:
        return await core_get_user_by_third_party_info(self, third_party_id, third_party_user_id)

    async def sign_in_up(self, third_party_id: str, third_party_user_id: str, email: str, email_verified: bool) -> SignInUpResponse:
        return await core_sign_in_up(self, third_party_id, third_party_user_id, email, email_verified)

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
