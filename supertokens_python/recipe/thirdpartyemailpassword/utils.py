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
    EmailDeliveryConfig,
    EmailDeliveryConfigWithService,
)
from supertokens_python.recipe.emailpassword.interfaces import (
    RecipeInterface as EPRecipeInterface,
)
from supertokens_python.recipe.thirdparty.provider import Provider
from supertokens_python.utils import deprecated_warn

from ..emailpassword.utils import (
    InputResetPasswordUsingTokenFeature,
    InputSignUpFeature,
)
from ..emailverification.types import User as EmailVerificationUser
from .emaildelivery.services.backward_compatibility import BackwardCompatibilityService
from .interfaces import APIInterface, RecipeInterface
from .types import EmailTemplateVars, User

if TYPE_CHECKING:
    from .recipe import ThirdPartyEmailPasswordRecipe

from supertokens_python.recipe.emailverification.utils import (
    OverrideConfig as EmailVerificationOverrideConfig,
)
from supertokens_python.recipe.emailverification.utils import (
    ParentRecipeEmailVerificationConfig,
)


class InputEmailVerificationConfig:
    def __init__(
        self,
        get_email_verification_url: Union[
            Callable[[User, Any], Awaitable[str]], None
        ] = None,
        create_and_send_custom_email: Union[
            Callable[[User, str, Any], Awaitable[None]], None
        ] = None,
    ):
        self.get_email_verification_url = get_email_verification_url
        self.create_and_send_custom_email = create_and_send_custom_email
        if create_and_send_custom_email:
            deprecated_warn(
                "create_and_send_custom_email is depricated. Please use email delivery config instead"
            )


def email_verification_create_and_send_custom_email(
    recipe: ThirdPartyEmailPasswordRecipe,
    create_and_send_custom_email: Callable[
        [User, str, Dict[str, Any]], Awaitable[None]
    ],
) -> Callable[[EmailVerificationUser, str, Dict[str, Any]], Awaitable[None]]:
    async def func(
        user: EmailVerificationUser, link: str, user_context: Dict[str, Any]
    ):
        user_info = await recipe.recipe_implementation.get_user_by_id(
            user.user_id, user_context
        )
        if user_info is None:
            raise Exception("Unknown User ID provided")
        return await create_and_send_custom_email(user_info, link, user_context)

    return func


def email_verification_get_email_verification_url(
    recipe: ThirdPartyEmailPasswordRecipe,
    get_email_verification_url: Callable[[User, Any], Awaitable[str]],
) -> Callable[[EmailVerificationUser, Any], Awaitable[str]]:
    async def func(user: EmailVerificationUser, user_context: Dict[str, Any]):
        user_info = await recipe.recipe_implementation.get_user_by_id(
            user.user_id, user_context
        )
        if user_info is None:
            raise Exception("Unknown User ID provided")
        return await get_email_verification_url(user_info, user_context)

    return func


def validate_and_normalise_email_verification_config(
    recipe: ThirdPartyEmailPasswordRecipe,
    config: Union[InputEmailVerificationConfig, None],
    override: InputOverrideConfig,
) -> ParentRecipeEmailVerificationConfig:
    create_and_send_custom_email = None
    get_email_verification_url = None
    if config is None:
        config = InputEmailVerificationConfig()
    if config.create_and_send_custom_email is not None:
        create_and_send_custom_email = email_verification_create_and_send_custom_email(
            recipe, config.create_and_send_custom_email
        )
    if config.get_email_verification_url is not None:
        get_email_verification_url = email_verification_get_email_verification_url(
            recipe, config.get_email_verification_url
        )

    return ParentRecipeEmailVerificationConfig(
        get_email_for_user_id=recipe.get_email_for_user_id,
        create_and_send_custom_email=create_and_send_custom_email,
        get_email_verification_url=get_email_verification_url,
        override=override.email_verification_feature,
    )


class InputOverrideConfig:
    def __init__(
        self,
        functions: Union[Callable[[RecipeInterface], RecipeInterface], None] = None,
        apis: Union[Callable[[APIInterface], APIInterface], None] = None,
        email_verification_feature: Union[EmailVerificationOverrideConfig, None] = None,
    ):
        self.functions = functions
        self.apis = apis
        self.email_verification_feature = email_verification_feature


class OverrideConfig:
    def __init__(
        self,
        functions: Union[Callable[[RecipeInterface], RecipeInterface], None] = None,
        apis: Union[Callable[[APIInterface], APIInterface], None] = None,
    ):
        self.functions = functions
        self.apis = apis


class ThirdPartyEmailPasswordConfig:
    def __init__(
        self,
        providers: List[Provider],
        email_verification_feature: ParentRecipeEmailVerificationConfig,
        sign_up_feature: Union[InputSignUpFeature, None],
        reset_password_using_token_feature: Union[
            InputResetPasswordUsingTokenFeature, None
        ],
        get_email_delivery_config: Callable[
            [RecipeInterface, EPRecipeInterface],
            EmailDeliveryConfigWithService[EmailTemplateVars],
        ],
        override: OverrideConfig,
    ):
        self.sign_up_feature = sign_up_feature
        self.email_verification_feature = email_verification_feature
        self.providers = providers
        self.reset_password_using_token_feature = reset_password_using_token_feature
        self.get_email_delivery_config = get_email_delivery_config
        self.override = override


def validate_and_normalise_user_input(
    recipe: ThirdPartyEmailPasswordRecipe,
    sign_up_feature: Union[InputSignUpFeature, None] = None,
    reset_password_using_token_feature: Union[
        InputResetPasswordUsingTokenFeature, None
    ] = None,
    email_verification_feature: Union[InputEmailVerificationConfig, None] = None,
    override: Union[InputOverrideConfig, None] = None,
    providers: Union[List[Provider], None] = None,
    email_delivery: Union[EmailDeliveryConfig[EmailTemplateVars], None] = None,
) -> ThirdPartyEmailPasswordConfig:
    if sign_up_feature is not None and not isinstance(sign_up_feature, InputSignUpFeature):  # type: ignore
        raise ValueError("sign_up_feature must be of type InputSignUpFeature or None")

    if reset_password_using_token_feature is not None and not isinstance(reset_password_using_token_feature, InputResetPasswordUsingTokenFeature):  # type: ignore
        raise ValueError(
            "reset_password_using_token_feature must be of type InputResetPasswordUsingTokenFeature or None"
        )

    if email_verification_feature is not None and not isinstance(email_verification_feature, InputEmailVerificationConfig):  # type: ignore
        raise ValueError(
            "email_verification_feature must be of type InputEmailVerificationConfig or None"
        )

    if override is not None and not isinstance(override, InputOverrideConfig):  # type: ignore
        raise ValueError("override must be of type InputOverrideConfig or None")

    if providers is not None and not isinstance(providers, List):  # type: ignore
        raise ValueError("providers must be of type List[Provider] or None")

    for provider in providers or []:
        if not isinstance(provider, Provider):  # type: ignore
            raise ValueError("providers must be of type List[Provider] or None")

    if providers is None:
        providers = []
    if override is None:
        override = InputOverrideConfig()

    def get_email_delivery_config(
        recipe_interface_impl: RecipeInterface,
        ep_recipe_interface_impl: EPRecipeInterface,
    ):
        if email_delivery and email_delivery.service:
            return EmailDeliveryConfigWithService(
                service=email_delivery.service, override=email_delivery.override
            )

        email_service = BackwardCompatibilityService(
            app_info=recipe.app_info,
            recipe_interface_impl=recipe_interface_impl,
            ep_recipe_interface_impl=ep_recipe_interface_impl,
            reset_password_using_token_feature=reset_password_using_token_feature,
            email_verification_feature=email_verification_feature,
        )
        if email_delivery is not None and email_delivery.override is not None:
            override = email_delivery.override
        else:
            override = None

        return EmailDeliveryConfigWithService(email_service, override=override)

    return ThirdPartyEmailPasswordConfig(
        providers,
        validate_and_normalise_email_verification_config(
            recipe, email_verification_feature, override
        ),
        sign_up_feature,
        reset_password_using_token_feature,
        get_email_delivery_config,
        OverrideConfig(functions=override.functions, apis=override.apis),
    )
