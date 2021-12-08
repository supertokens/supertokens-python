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

from typing import List, Callable, TYPE_CHECKING, Union

from supertokens_python.recipe.thirdparty.provider import Provider

from .interfaces import RecipeInterface, APIInterface
from .types import (
    NextPaginationToken
)
from ..emailpassword.utils import InputSignUpFeature, InputResetPasswordUsingTokenFeature

if TYPE_CHECKING:
    from .recipe import ThirdPartyEmailPasswordRecipe
from supertokens_python.utils import utf_base64decode, utf_base64encode
from supertokens_python.recipe.emailpassword.types import UsersResponse
from supertokens_python.recipe.emailverification.utils import (
    InputEmailVerificationConfig, ParentRecipeEmailVerificationConfig,
    OverrideConfig as EmailVerificationOverrideConfig
)


def email_verification_create_and_send_custom_email(recipe: ThirdPartyEmailPasswordRecipe,
                                                    create_and_send_custom_email):
    async def func(user, link):
        user_info = await recipe.recipe_implementation.get_user_by_id(user.id)
        if user_info is None:
            raise Exception('User ID unknown')
        return await create_and_send_custom_email(user_info, link)

    return func


def email_verification_get_email_verification_url(
        recipe: ThirdPartyEmailPasswordRecipe, get_email_verification_url):
    async def func(user):
        user_info = await recipe.recipe_implementation.get_user_by_id(user.id)
        if user_info is None:
            raise Exception('User ID unknown')
        return await get_email_verification_url(user_info)

    return func


def validate_and_normalise_email_verification_config(
        recipe: ThirdPartyEmailPasswordRecipe, config: Union[InputEmailVerificationConfig, None],
        override: InputOverrideConfig):
    create_and_send_custom_email = None
    get_email_verification_url = None
    if config is None:
        config = InputEmailVerificationConfig()
    if config.create_and_send_custom_email is not None:
        create_and_send_custom_email = email_verification_create_and_send_custom_email(recipe,
                                                                                       config.create_and_send_custom_email)
    if config.get_email_verification_url is not None:
        get_email_verification_url = email_verification_get_email_verification_url(recipe,
                                                                                   config.get_email_verification_url)

    return ParentRecipeEmailVerificationConfig(
        get_email_for_user_id=recipe.get_email_for_user_id,
        create_and_send_custom_email=create_and_send_custom_email,
        get_email_verification_url=get_email_verification_url,
        override=override.email_verification_feature
    )


class InputOverrideConfig:
    def __init__(self, functions: Union[Callable[[RecipeInterface], RecipeInterface], None] = None,
                 apis: Union[Callable[[APIInterface], APIInterface], None] = None,
                 email_verification_feature: Union[EmailVerificationOverrideConfig, None] = None):
        self.functions = functions
        self.apis = apis
        self.email_verification_feature = email_verification_feature


class OverrideConfig:
    def __init__(self, functions: Union[Callable[[RecipeInterface], RecipeInterface], None] = None,
                 apis: Union[Callable[[APIInterface], APIInterface], None] = None):
        self.functions = functions
        self.apis = apis


class ThirdPartyEmailPasswordConfig:
    def __init__(self,
                 providers: List[Provider],
                 email_verification_feature: ParentRecipeEmailVerificationConfig,
                 sign_up_feature: Union[InputSignUpFeature, None],
                 reset_password_using_token_feature: Union[InputResetPasswordUsingTokenFeature, None],
                 override: Union[OverrideConfig, None]):
        self.sign_up_feature = sign_up_feature
        self.email_verification_feature = email_verification_feature
        self.providers = providers
        self.reset_password_using_token_feature = reset_password_using_token_feature
        self.override = override


def validate_and_normalise_user_input(
        recipe: ThirdPartyEmailPasswordRecipe,
        sign_up_feature: Union[InputSignUpFeature, None] = None,
        reset_password_using_token_feature: Union[InputResetPasswordUsingTokenFeature, None] = None,
        email_verification_feature: Union[InputEmailVerificationConfig, None] = None,
        override: Union[InputOverrideConfig, None] = None,
        providers: Union[List[Provider], None] = None
) -> ThirdPartyEmailPasswordConfig:
    if providers is None:
        providers = []
    if override is None:
        override = InputOverrideConfig()
    email_verification_feature = validate_and_normalise_email_verification_config(
        recipe,
        email_verification_feature,
        override
    )
    return ThirdPartyEmailPasswordConfig(providers, email_verification_feature, sign_up_feature,
                                         reset_password_using_token_feature,
                                         OverrideConfig(functions=override.functions, apis=override.apis)
                                         )


def create_new_pagination_token(user_id: str, time_joined: int) -> str:
    return utf_base64encode(user_id + ';' + str(time_joined))


def combine_pagination_tokens(third_party_pagination_token: Union[str, None],
                              email_password_pagination_token: Union[str, None]):
    if third_party_pagination_token is None:
        third_party_pagination_token = 'null'
    if email_password_pagination_token is None:
        email_password_pagination_token = 'null'
    return utf_base64encode(third_party_pagination_token + ';' + email_password_pagination_token)


def extract_pagination_token(
        next_pagination_token: str) -> NextPaginationToken:
    extracted_tokens = utf_base64decode(next_pagination_token).split(';')
    if len(extracted_tokens) != 2:
        raise Exception('Pagination token is invalid')
    return NextPaginationToken(None if extracted_tokens[0] == 'null' else extracted_tokens[0],
                               None if extracted_tokens[1] == 'null' else extracted_tokens[1])


def combine_pagination_results(third_party_result: UsersResponse, email_password_result: UsersResponse, limit: int,
                               oldest_first: bool) -> UsersResponse:
    max_loop = min(
        limit, len(
            third_party_result.users), len(
            email_password_result.users))
    third_party_result_loop_index = 0
    email_password_result_loop_index = 0
    users = []
    for i in range(max_loop):
        if (
                third_party_result_loop_index != len(third_party_result.users)
                and
                (
                    email_password_result_loop_index == len(
                        email_password_result.users)
                    or
                    (
                        oldest_first and third_party_result.users[third_party_result_loop_index].time_joined <
                        email_password_result.users[email_password_result_loop_index].time_joined
                    )
                    or
                    (
                        not oldest_first and third_party_result.users[
                            third_party_result_loop_index].time_joined >
                        email_password_result.users[email_password_result_loop_index].time_joined
                    )
                )
        ):
            users.append(
                third_party_result.users[third_party_result_loop_index])
            third_party_result_loop_index += 1
        else:
            users.append(
                email_password_result.users[third_party_result_loop_index])
            email_password_result_loop_index += 1

    if third_party_result_loop_index == len(third_party_result.users):
        third_party_pagination_token = third_party_result.next_pagination_token
    else:
        third_party_pagination_token = create_new_pagination_token(
            third_party_result.users[third_party_result_loop_index].user_id,
            third_party_result.users[third_party_result_loop_index].time_joined
        )
    if email_password_result_loop_index == len(email_password_result.users):
        email_password_pagination_token = email_password_result.next_pagination_token
    else:
        email_password_pagination_token = create_new_pagination_token(
            email_password_result.users[email_password_result_loop_index].user_id,
            email_password_result.users[email_password_result_loop_index].time_joined
        )
    next_pagination_token = combine_pagination_tokens(
        third_party_pagination_token, email_password_pagination_token)
    return UsersResponse(users, next_pagination_token)
