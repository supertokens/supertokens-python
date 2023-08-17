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
from supertokens_python.ingredients.smsdelivery.types import (
    SMSDeliveryConfig,
    SMSDeliveryConfigWithService,
)
from supertokens_python.recipe.thirdparty.provider import ProviderInput
from supertokens_python.recipe.thirdpartypasswordless.emaildelivery.services.backward_compatibility import (
    BackwardCompatibilityService,
)
from supertokens_python.recipe.thirdpartypasswordless.types import SMSTemplateVars
from typing_extensions import Literal

from ..passwordless.utils import (
    ContactConfig,
)

if TYPE_CHECKING:
    from .recipe import ThirdPartyPasswordlessRecipe
    from .interfaces import APIInterface, RecipeInterface
    from .types import EmailTemplateVars

from .smsdelivery.services.backward_compatibility import (
    BackwardCompatibilityService as SMSBackwardCompatibilityService,
)


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


class ThirdPartyPasswordlessConfig:
    def __init__(
        self,
        override: OverrideConfig,
        providers: List[ProviderInput],
        contact_config: ContactConfig,
        flow_type: Literal[
            "USER_INPUT_CODE", "MAGIC_LINK", "USER_INPUT_CODE_AND_MAGIC_LINK"
        ],
        get_email_delivery_config: Callable[
            [], EmailDeliveryConfigWithService[EmailTemplateVars]
        ],
        get_sms_delivery_config: Callable[
            [], SMSDeliveryConfigWithService[SMSTemplateVars]
        ],
        get_custom_user_input_code: Union[
            Callable[[str, Dict[str, Any]], Awaitable[str]], None
        ] = None,
    ):
        self.providers = providers
        self.contact_config = contact_config
        self.flow_type: Literal[
            "USER_INPUT_CODE", "MAGIC_LINK", "USER_INPUT_CODE_AND_MAGIC_LINK"
        ] = flow_type
        self.get_custom_user_input_code = get_custom_user_input_code
        self.get_email_delivery_config = get_email_delivery_config
        self.get_sms_delivery_config = get_sms_delivery_config
        self.override = override


def validate_and_normalise_user_input(
    recipe: ThirdPartyPasswordlessRecipe,
    contact_config: ContactConfig,
    flow_type: Literal[
        "USER_INPUT_CODE", "MAGIC_LINK", "USER_INPUT_CODE_AND_MAGIC_LINK"
    ],
    get_custom_user_input_code: Union[
        Callable[[str, Dict[str, Any]], Awaitable[str]], None
    ] = None,
    override: Union[InputOverrideConfig, None] = None,
    providers: Union[List[ProviderInput], None] = None,
    email_delivery: Union[EmailDeliveryConfig[EmailTemplateVars], None] = None,
    sms_delivery: Union[SMSDeliveryConfig[SMSTemplateVars], None] = None,
) -> ThirdPartyPasswordlessConfig:
    if not isinstance(contact_config, ContactConfig):  # type: ignore
        raise ValueError("contact_config must be an instance of ContactConfig")

    if flow_type not in {"USER_INPUT_CODE", "MAGIC_LINK", "USER_INPUT_CODE_AND_MAGIC_LINK"}:  # type: ignore
        raise ValueError(
            "flow_type must be one of USER_INPUT_CODE, MAGIC_LINK, USER_INPUT_CODE_AND_MAGIC_LINK"
        )

    if override is not None and not isinstance(override, InputOverrideConfig):  # type: ignore
        raise ValueError("override must be an instance of InputOverrideConfig or None")

    if providers is not None and not isinstance(providers, List):  # type: ignore
        raise ValueError("providers must be of type List[ProviderInput] or None")

    if providers is None:
        providers = []

    for provider in providers:
        if not isinstance(provider, ProviderInput):  # type: ignore
            raise ValueError("providers must be of type List[ProviderInput] or None")

    if override is None:
        override = InputOverrideConfig()

    def get_email_delivery_config() -> EmailDeliveryConfigWithService[
        EmailTemplateVars
    ]:
        email_service = email_delivery.service if email_delivery is not None else None

        if email_service is None:
            email_service = BackwardCompatibilityService(recipe.app_info)

        if email_delivery is not None and email_delivery.override is not None:
            override = email_delivery.override
        else:
            override = None

        return EmailDeliveryConfigWithService(email_service, override=override)

    def get_sms_delivery_config() -> SMSDeliveryConfigWithService[SMSTemplateVars]:
        if sms_delivery and sms_delivery.service:
            return SMSDeliveryConfigWithService(
                service=sms_delivery.service, override=sms_delivery.override
            )

        sms_service = SMSBackwardCompatibilityService(recipe.app_info)

        if sms_delivery is not None and sms_delivery.override is not None:
            override = sms_delivery.override
        else:
            override = None

        return SMSDeliveryConfigWithService(sms_service, override=override)

    return ThirdPartyPasswordlessConfig(
        override=OverrideConfig(functions=override.functions, apis=override.apis),
        providers=providers,
        contact_config=contact_config,
        flow_type=flow_type,
        get_custom_user_input_code=get_custom_user_input_code,
        get_email_delivery_config=get_email_delivery_config,
        get_sms_delivery_config=get_sms_delivery_config,
    )
