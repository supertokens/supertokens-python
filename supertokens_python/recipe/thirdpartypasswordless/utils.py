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
from typing_extensions import Literal

from ..emailverification.types import User as EmailVerificationUser
from ..passwordless.utils import (ContactConfig, PhoneOrEmailInput,
                                  default_get_link_domain_and_path)
from .interfaces import APIInterface, RecipeInterface
from .types import User

if TYPE_CHECKING:
    from .recipe import ThirdPartyPasswordlessRecipe

from supertokens_python.recipe.emailverification.utils import \
    OverrideConfig as EmailVerificationOverrideConfig
from supertokens_python.recipe.emailverification.utils import \
    ParentRecipeEmailVerificationConfig


class InputEmailVerificationConfig:
    """InputEmailVerificationConfig.
    """

    def __init__(self,
                 get_email_verification_url: Union[Callable[[
                     User, Any], Awaitable[str]], None] = None,
                 create_and_send_custom_email: Union[Callable[[
                     User, str, Any], Awaitable[None]], None] = None
                 ):
        """__init__.

        Parameters
        ----------
        get_email_verification_url : Union[Callable[[
                             User, Any], Awaitable[str]], None]
            get_email_verification_url
        create_and_send_custom_email : Union[Callable[[
                             User, str, Any], Awaitable[None]], None]
            create_and_send_custom_email
        """
        self.get_email_verification_url = get_email_verification_url
        self.create_and_send_custom_email = create_and_send_custom_email


def email_verification_create_and_send_custom_email(
        recipe: ThirdPartyPasswordlessRecipe, create_and_send_custom_email: Callable[[
            User, str, Dict[str, Any]], Awaitable[None]]) -> Callable[[
                EmailVerificationUser, str, Dict[str, Any]], Awaitable[None]]:
    """email_verification_create_and_send_custom_email.

    Parameters
    ----------
    recipe : ThirdPartyPasswordlessRecipe
        recipe
    create_and_send_custom_email : Callable[[
                User, str, Dict[str, Any]], Awaitable[None]]
        create_and_send_custom_email

    Returns
    -------
    Callable[[
                    EmailVerificationUser, str, Dict[str, Any]], Awaitable[None]]

    """
    async def func(user: EmailVerificationUser, link: str, user_context: Dict[str, Any]):
        """func.

        Parameters
        ----------
        user : EmailVerificationUser
            user
        link : str
            link
        user_context : Dict[str, Any]
            user_context
        """
        user_info = await recipe.recipe_implementation.get_user_by_id(user.user_id, user_context)
        if user_info is None:
            raise Exception('Unknown User ID provided')
        return await create_and_send_custom_email(user_info, link, user_context)

    return func


def email_verification_get_email_verification_url(
        recipe: ThirdPartyPasswordlessRecipe, get_email_verification_url: Callable[[
            User, Any], Awaitable[str]]) -> Callable[[
                EmailVerificationUser, Any], Awaitable[str]]:
    """email_verification_get_email_verification_url.

    Parameters
    ----------
    recipe : ThirdPartyPasswordlessRecipe
        recipe
    get_email_verification_url : Callable[[
                User, Any], Awaitable[str]]
        get_email_verification_url

    Returns
    -------
    Callable[[
                    EmailVerificationUser, Any], Awaitable[str]]

    """
    async def func(user: EmailVerificationUser, user_context: Dict[str, Any]):
        """func.

        Parameters
        ----------
        user : EmailVerificationUser
            user
        user_context : Dict[str, Any]
            user_context
        """
        user_info = await recipe.recipe_implementation.get_user_by_id(user.user_id, user_context)
        if user_info is None:
            raise Exception('Unknown User ID provided')
        return await get_email_verification_url(user_info, user_context)

    return func


def validate_and_normalise_email_verification_config(
        recipe: ThirdPartyPasswordlessRecipe, config: Union[InputEmailVerificationConfig, None],
        override: InputOverrideConfig) -> ParentRecipeEmailVerificationConfig:
    """validate_and_normalise_email_verification_config.

    Parameters
    ----------
    recipe : ThirdPartyPasswordlessRecipe
        recipe
    config : Union[InputEmailVerificationConfig, None]
        config
    override : InputOverrideConfig
        override

    Returns
    -------
    ParentRecipeEmailVerificationConfig

    """
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
    """InputOverrideConfig.
    """

    def __init__(self, functions: Union[Callable[[RecipeInterface], RecipeInterface], None] = None,
                 apis: Union[Callable[[APIInterface],
                                      APIInterface], None] = None,
                 email_verification_feature: Union[EmailVerificationOverrideConfig, None] = None):
        """__init__.

        Parameters
        ----------
        functions : Union[Callable[[RecipeInterface], RecipeInterface], None]
            functions
        apis : Union[Callable[[APIInterface],
                                              APIInterface], None]
            apis
        email_verification_feature : Union[EmailVerificationOverrideConfig, None]
            email_verification_feature
        """
        self.functions = functions
        self.apis = apis
        self.email_verification_feature = email_verification_feature


class OverrideConfig:
    """OverrideConfig.
    """

    def __init__(self, functions: Union[Callable[[RecipeInterface], RecipeInterface], None] = None,
                 apis: Union[Callable[[APIInterface], APIInterface], None] = None):
        """__init__.

        Parameters
        ----------
        functions : Union[Callable[[RecipeInterface], RecipeInterface], None]
            functions
        apis : Union[Callable[[APIInterface], APIInterface], None]
            apis
        """
        self.functions = functions
        self.apis = apis


class ThirdPartyPasswordlessConfig:
    """ThirdPartyPasswordlessConfig.
    """

    def __init__(self,
                 override: OverrideConfig,
                 providers: List[Provider],
                 email_verification_feature: ParentRecipeEmailVerificationConfig,
                 contact_config: ContactConfig,
                 flow_type: Literal['USER_INPUT_CODE', 'MAGIC_LINK', 'USER_INPUT_CODE_AND_MAGIC_LINK'],
                 get_link_domain_and_path: Callable[[PhoneOrEmailInput, Dict[str, Any]], Awaitable[str]],
                 get_custom_user_input_code: Union[Callable[[
                     Dict[str, Any]], Awaitable[str]], None] = None):
        """__init__.

        Parameters
        ----------
        override : OverrideConfig
            override
        providers : List[Provider]
            providers
        email_verification_feature : ParentRecipeEmailVerificationConfig
            email_verification_feature
        contact_config : ContactConfig
            contact_config
        flow_type : Literal['USER_INPUT_CODE', 'MAGIC_LINK', 'USER_INPUT_CODE_AND_MAGIC_LINK']
            flow_type
        get_link_domain_and_path : Callable[[PhoneOrEmailInput, Dict[str, Any]], Awaitable[str]]
            get_link_domain_and_path
        get_custom_user_input_code : Union[Callable[[
                             Dict[str, Any]], Awaitable[str]], None]
            get_custom_user_input_code
        """
        self.email_verification_feature = email_verification_feature
        self.providers = providers
        self.contact_config = contact_config
        self.flow_type: Literal['USER_INPUT_CODE', 'MAGIC_LINK', 'USER_INPUT_CODE_AND_MAGIC_LINK'] = flow_type
        self.get_link_domain_and_path = get_link_domain_and_path
        self.get_custom_user_input_code = get_custom_user_input_code
        self.override = override


def validate_and_normalise_user_input(
        recipe: ThirdPartyPasswordlessRecipe,
        contact_config: ContactConfig,
        flow_type: Literal['USER_INPUT_CODE', 'MAGIC_LINK', 'USER_INPUT_CODE_AND_MAGIC_LINK'],
        get_link_domain_and_path: Union[Callable[[
            PhoneOrEmailInput, Dict[str, Any]], Awaitable[str]], None] = None,
        get_custom_user_input_code: Union[Callable[[Dict[str, Any]], Awaitable[str]], None] = None,
        email_verification_feature: Union[InputEmailVerificationConfig, None] = None,
        override: Union[InputOverrideConfig, None] = None,
        providers: Union[List[Provider], None] = None
) -> ThirdPartyPasswordlessConfig:
    """validate_and_normalise_user_input.

    Parameters
    ----------
    recipe : ThirdPartyPasswordlessRecipe
        recipe
    contact_config : ContactConfig
        contact_config
    flow_type : Literal['USER_INPUT_CODE', 'MAGIC_LINK', 'USER_INPUT_CODE_AND_MAGIC_LINK']
        flow_type
    get_link_domain_and_path : Union[Callable[[
                PhoneOrEmailInput, Dict[str, Any]], Awaitable[str]], None]
        get_link_domain_and_path
    get_custom_user_input_code : Union[Callable[[Dict[str, Any]], Awaitable[str]], None]
        get_custom_user_input_code
    email_verification_feature : Union[InputEmailVerificationConfig, None]
        email_verification_feature
    override : Union[InputOverrideConfig, None]
        override
    providers : Union[List[Provider], None]
        providers

    Returns
    -------
    ThirdPartyPasswordlessConfig

    """
    if providers is None:
        providers = []
    if override is None:
        override = InputOverrideConfig()

    if get_link_domain_and_path is None:
        get_link_domain_and_path = default_get_link_domain_and_path(recipe.app_info)

    return ThirdPartyPasswordlessConfig(override=OverrideConfig(functions=override.functions, apis=override.apis), providers=providers, contact_config=contact_config, flow_type=flow_type, get_link_domain_and_path=get_link_domain_and_path, get_custom_user_input_code=get_custom_user_input_code, email_verification_feature=validate_and_normalise_email_verification_config(recipe, email_verification_feature, override))
