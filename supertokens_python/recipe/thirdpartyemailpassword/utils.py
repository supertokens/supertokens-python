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

from typing import TYPE_CHECKING, Callable, List, Union

from supertokens_python.ingredients.emaildelivery.types import (
    EmailDeliveryConfig,
    EmailDeliveryConfigWithService,
)
from supertokens_python.recipe.emailpassword.interfaces import (
    RecipeInterface as EPRecipeInterface,
)
from supertokens_python.recipe.thirdparty.provider import ProviderInput

from ..emailpassword.utils import (
    InputSignUpFeature,
)
from .emaildelivery.services.backward_compatibility import BackwardCompatibilityService
from .interfaces import APIInterface, RecipeInterface
from .types import EmailTemplateVars

if TYPE_CHECKING:
    from .recipe import ThirdPartyEmailPasswordRecipe


class InputOverrideConfig:
    def __init__(
        self,
        functions: Union[Callable[[RecipeInterface], RecipeInterface], None] = None,
        apis: Union[Callable[[APIInterface], APIInterface], None] = None,
    ):
        self.functions = functions
        self.apis = apis


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
        providers: List[ProviderInput],
        sign_up_feature: Union[InputSignUpFeature, None],
        get_email_delivery_config: Callable[
            [EPRecipeInterface],
            EmailDeliveryConfigWithService[EmailTemplateVars],
        ],
        override: OverrideConfig,
    ):
        self.sign_up_feature = sign_up_feature
        self.providers = providers
        self.get_email_delivery_config = get_email_delivery_config
        self.override = override


def validate_and_normalise_user_input(
    recipe: ThirdPartyEmailPasswordRecipe,
    sign_up_feature: Union[InputSignUpFeature, None] = None,
    override: Union[InputOverrideConfig, None] = None,
    providers: Union[List[ProviderInput], None] = None,
    email_delivery: Union[EmailDeliveryConfig[EmailTemplateVars], None] = None,
) -> ThirdPartyEmailPasswordConfig:
    if sign_up_feature is not None and not isinstance(sign_up_feature, InputSignUpFeature):  # type: ignore
        raise ValueError("sign_up_feature must be of type InputSignUpFeature or None")

    if override is not None and not isinstance(override, InputOverrideConfig):  # type: ignore
        raise ValueError("override must be of type InputOverrideConfig or None")

    if providers is not None and not isinstance(providers, List):  # type: ignore
        raise ValueError("providers must be of type List[ProviderInput] or None")

    for provider in providers or []:
        if not isinstance(provider, ProviderInput):  # type: ignore
            raise ValueError("providers must be of type List[ProviderInput] or None")

    if providers is None:
        providers = []
    if override is None:
        override = InputOverrideConfig()

    def get_email_delivery_config(
        ep_recipe_interface_impl: EPRecipeInterface,
    ):
        if email_delivery and email_delivery.service:
            return EmailDeliveryConfigWithService(
                service=email_delivery.service, override=email_delivery.override
            )

        email_service = BackwardCompatibilityService(
            app_info=recipe.app_info,
            ep_recipe_interface_impl=ep_recipe_interface_impl,
        )
        if email_delivery is not None and email_delivery.override is not None:
            override = email_delivery.override
        else:
            override = None

        return EmailDeliveryConfigWithService(email_service, override=override)

    return ThirdPartyEmailPasswordConfig(
        providers,
        sign_up_feature,
        get_email_delivery_config,
        OverrideConfig(functions=override.functions, apis=override.apis),
    )
