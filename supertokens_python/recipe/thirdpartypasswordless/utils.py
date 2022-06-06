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

from supertokens_python.ingredients.emaildelivery.types import (
    EmailDeliveryConfig, EmailDeliveryConfigWithService)
from supertokens_python.ingredients.smsdelivery.types import (
    SMSDeliveryConfig, SMSDeliveryConfigWithService)
from supertokens_python.recipe.passwordless import (ContactEmailOnlyConfig,
                                                    ContactEmailOrPhoneConfig,
                                                    ContactPhoneOnlyConfig)
from supertokens_python.recipe.thirdparty.provider import Provider
from supertokens_python.recipe.thirdpartypasswordless.emaildelivery.service.backward_compatibility import \
    BackwardCompatibilityService
from supertokens_python.recipe.thirdpartypasswordless.types import \
    TypeThirdPartyPasswordlessSmsDeliveryInput
from typing_extensions import Literal

from ..emailverification.types import User as EmailVerificationUser
from ..passwordless.utils import (ContactConfig, ContactEmailOrPhoneConfig,
                                  ContactPhoneOnlyConfig, PhoneOrEmailInput,
                                  default_get_link_domain_and_path)

if TYPE_CHECKING:
    from .recipe import ThirdPartyPasswordlessRecipe
    from .interfaces import APIInterface, RecipeInterface
    from .types import TypeThirdPartyPasswordlessEmailDeliveryInput, User

from supertokens_python.recipe.emailverification.utils import \
    OverrideConfig as EmailVerificationOverrideConfig
from supertokens_python.recipe.emailverification.utils import \
    ParentRecipeEmailVerificationConfig

from .smsdelivery.service.backward_compatibility import \
    BackwardCompatibilityService as SMSBackwardCompatibilityService


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
        recipe: ThirdPartyPasswordlessRecipe, create_and_send_custom_email: Callable[[
            User, str, Dict[str, Any]], Awaitable[None]]) -> Callable[[
                EmailVerificationUser, str, Dict[str, Any]], Awaitable[None]]:
    async def func(user: EmailVerificationUser, link: str, user_context: Dict[str, Any]):
        user_info = await recipe.recipe_implementation.get_user_by_id(user.user_id, user_context)
        if user_info is None:
            raise Exception('Unknown User ID provided')
        return await create_and_send_custom_email(user_info, link, user_context)

    return func


def email_verification_get_email_verification_url(
        recipe: ThirdPartyPasswordlessRecipe, get_email_verification_url: Callable[[
            User, Any], Awaitable[str]]) -> Callable[[
                EmailVerificationUser, Any], Awaitable[str]]:
    async def func(user: EmailVerificationUser, user_context: Dict[str, Any]):
        user_info = await recipe.recipe_implementation.get_user_by_id(user.user_id, user_context)
        if user_info is None:
            raise Exception('Unknown User ID provided')
        return await get_email_verification_url(user_info, user_context)

    return func


def validate_and_normalise_email_verification_config(
        recipe: ThirdPartyPasswordlessRecipe, config: Union[InputEmailVerificationConfig, None],
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


class ThirdPartyPasswordlessConfig:
    def __init__(self,
                 override: OverrideConfig,
                 providers: List[Provider],
                 email_verification_feature: ParentRecipeEmailVerificationConfig,
                 contact_config: ContactConfig,
                 flow_type: Literal['USER_INPUT_CODE', 'MAGIC_LINK', 'USER_INPUT_CODE_AND_MAGIC_LINK'],
                 get_link_domain_and_path: Callable[[PhoneOrEmailInput, Dict[str, Any]], Awaitable[str]],
                 get_email_delivery_config: Callable[
                     [RecipeInterface], EmailDeliveryConfigWithService[TypeThirdPartyPasswordlessEmailDeliveryInput]
                 ],
                 get_sms_delivery_config: Callable[
                     [], SMSDeliveryConfigWithService[TypeThirdPartyPasswordlessSmsDeliveryInput]
                 ],
                 get_custom_user_input_code: Union[Callable[[Dict[str, Any]], Awaitable[str]], None] = None
                 ):
        self.email_verification_feature = email_verification_feature
        self.providers = providers
        self.contact_config = contact_config
        self.flow_type: Literal['USER_INPUT_CODE', 'MAGIC_LINK', 'USER_INPUT_CODE_AND_MAGIC_LINK'] = flow_type
        self.get_link_domain_and_path = get_link_domain_and_path
        self.get_custom_user_input_code = get_custom_user_input_code
        self.get_email_delivery_config = get_email_delivery_config
        self.get_sms_delivery_config = get_sms_delivery_config
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
        providers: Union[List[Provider], None] = None,
        email_delivery_config: Union[EmailDeliveryConfig[TypeThirdPartyPasswordlessEmailDeliveryInput], None] = None,
        sms_delivery_config: Union[SMSDeliveryConfig[TypeThirdPartyPasswordlessSmsDeliveryInput], None] = None,
) -> ThirdPartyPasswordlessConfig:
    if providers is None:
        providers = []
    if override is None:
        override = InputOverrideConfig()

    if get_link_domain_and_path is None:
        get_link_domain_and_path = default_get_link_domain_and_path(recipe.app_info)

    def get_email_delivery_config(
        tppless_recipe: RecipeInterface,
    ) -> EmailDeliveryConfigWithService[TypeThirdPartyPasswordlessEmailDeliveryInput]:
        email_service = email_delivery_config.service if email_delivery_config is not None else None
        if isinstance(contact_config, (ContactEmailOrPhoneConfig, ContactEmailOnlyConfig)):
            create_and_send_custom_email = contact_config.create_and_send_custom_email
        else:
            create_and_send_custom_email = None

        if email_service is None:
            ev_feature = email_verification_feature
            email_service = BackwardCompatibilityService(recipe.app_info, tppless_recipe, create_and_send_custom_email, ev_feature)

        if email_delivery_config is not None and email_delivery_config.override is not None:
            override = email_delivery_config.override
        else:
            override = None

        return EmailDeliveryConfigWithService(email_service, override=override)

    def get_sms_delivery_config() -> SMSDeliveryConfigWithService[TypeThirdPartyPasswordlessSmsDeliveryInput]:
        if sms_delivery_config and sms_delivery_config.service:
            return SMSDeliveryConfigWithService(
                service=sms_delivery_config.service,
                override=sms_delivery_config.override
            )

        if isinstance(contact_config, (ContactPhoneOnlyConfig, ContactEmailOrPhoneConfig)):
            pless_create_and_send_custom_text_message = contact_config.create_and_send_custom_text_message
        else:
            pless_create_and_send_custom_text_message = None

        sms_service = SMSBackwardCompatibilityService(
            recipe.app_info,
            pless_create_and_send_custom_text_message,
        )
        return SMSDeliveryConfigWithService(sms_service, override=None)

    return ThirdPartyPasswordlessConfig(
        override=OverrideConfig(functions=override.functions, apis=override.apis), providers=providers, contact_config=contact_config, flow_type=flow_type, get_link_domain_and_path=get_link_domain_and_path, get_custom_user_input_code=get_custom_user_input_code, email_verification_feature=validate_and_normalise_email_verification_config(
            recipe, email_verification_feature, override
        ),
        get_email_delivery_config=get_email_delivery_config,
        get_sms_delivery_config=get_sms_delivery_config,
    )
