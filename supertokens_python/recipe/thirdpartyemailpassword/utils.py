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

from typing import TYPE_CHECKING, Any, Awaitable, Callable, Dict, List, Union

from supertokens_python.recipe.thirdparty.provider import Provider

from ..emailpassword.utils import (InputResetPasswordUsingTokenFeature,
                                   InputSignUpFeature)
from ..emailverification.types import User as EmailVerificationUser
from .interfaces import APIInterface, RecipeInterface
from .types import User

if TYPE_CHECKING:
    from .recipe import ThirdPartyEmailPasswordRecipe

from supertokens_python.recipe.emailverification.utils import \
    OverrideConfig as EmailVerificationOverrideConfig
from supertokens_python.recipe.emailverification.utils import \
    ParentRecipeEmailVerificationConfig


class InputEmailVerificationConfig:
    def __init__(self,
                 get_email_verification_url: Union[Callable[[
                     User, Any], Awaitable[str]], None] = None,
                 create_and_send_custom_email: Union[Callable[[
                     User, str, Any], Awaitable[None]], None] = None
                 ):
        self.get_email_verification_url = get_email_verification_url
        self.create_and_send_custom_email = create_and_send_custom_email


def email_verification_create_and_send_custom_email(
        recipe: ThirdPartyEmailPasswordRecipe, create_and_send_custom_email: Callable[[
            User, str, Dict[str, Any]], Awaitable[None]]) -> Callable[[
                EmailVerificationUser, str, Dict[str, Any]], Awaitable[None]]:
    async def func(user: EmailVerificationUser, link: str, user_context: Dict[str, Any]):
        user_info = await recipe.recipe_implementation.get_user_by_id(user.user_id, user_context)
        if user_info is None:
            raise Exception('Unknown User ID provided')
        return await create_and_send_custom_email(user_info, link, user_context)

    return func


def email_verification_get_email_verification_url(
        recipe: ThirdPartyEmailPasswordRecipe, get_email_verification_url: Callable[[
            User, Any], Awaitable[str]]) -> Callable[[
                EmailVerificationUser, Any], Awaitable[str]]:
    async def func(user: EmailVerificationUser, user_context: Dict[str, Any]):
        user_info = await recipe.recipe_implementation.get_user_by_id(user.user_id, user_context)
        if user_info is None:
            raise Exception('Unknown User ID provided')
        return await get_email_verification_url(user_info, user_context)

    return func


def validate_and_normalise_email_verification_config(
        recipe: ThirdPartyEmailPasswordRecipe, config: Union[InputEmailVerificationConfig, None],
        override: InputOverrideConfig) -> ParentRecipeEmailVerificationConfig:
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
                 apis: Union[Callable[[APIInterface],
                                      APIInterface], None] = None,
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
                 override: OverrideConfig):
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
    return ThirdPartyEmailPasswordConfig(providers, validate_and_normalise_email_verification_config(recipe, email_verification_feature, override), sign_up_feature, reset_password_using_token_feature, OverrideConfig(functions=override.functions, apis=override.apis))
