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

from abc import ABC
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Dict, Union

from supertokens_python.ingredients.emaildelivery.types import (
    EmailDeliveryConfig,
    EmailDeliveryConfigWithService,
)
from supertokens_python.ingredients.smsdelivery.types import (
    SMSDeliveryConfig,
    SMSDeliveryConfigWithService,
)
from supertokens_python.recipe.passwordless.types import (
    PasswordlessLoginSMSTemplateVars,
)
from typing_extensions import Literal

if TYPE_CHECKING:
    from .interfaces import (
        APIInterface,
        RecipeInterface,
        PasswordlessLoginEmailTemplateVars,
    )
    from supertokens_python import AppInfo

from re import fullmatch

from phonenumbers import is_valid_number, parse  # type: ignore
from supertokens_python.recipe.passwordless.emaildelivery.services.backward_compatibility import (
    BackwardCompatibilityService,
)
from supertokens_python.recipe.passwordless.smsdelivery.services.backward_compatibility import (
    BackwardCompatibilityService as SMSBackwardCompatibilityService,
)


async def default_validate_phone_number(value: str, _tenant_id: str):
    try:
        parsed_phone_number: Any = parse(value, None)
        if not is_valid_number(parsed_phone_number):
            return "Phone number is invalid"
    except Exception:
        return "Phone number is invalid"


async def default_validate_email(value: str, _tenant_id: str):
    pattern = r"^(([^<>()\[\]\\.,;:\s@\"]+(\.[^<>()\[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$"
    if fullmatch(pattern, value) is None:
        return "Email is invalid"


class OverrideConfig:
    def __init__(
        self,
        functions: Union[Callable[[RecipeInterface], RecipeInterface], None] = None,
        apis: Union[Callable[[APIInterface], APIInterface], None] = None,
    ):
        self.functions = functions
        self.apis = apis


class ContactConfig(ABC):
    def __init__(self, contact_method: Literal["PHONE", "EMAIL", "EMAIL_OR_PHONE"]):
        self.contact_method = contact_method


class ContactPhoneOnlyConfig(ContactConfig):
    def __init__(
        self,
        validate_phone_number: Union[
            Callable[[str, str], Awaitable[Union[str, None]]], None
        ] = None,
    ):
        super().__init__("PHONE")

        if validate_phone_number is None:
            self.validate_phone_number = default_validate_phone_number
        else:
            self.validate_phone_number = validate_phone_number


class ContactEmailOnlyConfig(ContactConfig):
    def __init__(
        self,
        validate_email_address: Union[
            Callable[[str, str], Awaitable[Union[str, None]]], None
        ] = None,
    ):
        super().__init__("EMAIL")

        if validate_email_address is None:
            self.validate_email_address = default_validate_email
        else:
            self.validate_email_address = validate_email_address


class ContactEmailOrPhoneConfig(ContactConfig):
    def __init__(
        self,
        validate_email_address: Union[
            Callable[[str, str], Awaitable[Union[str, None]]], None
        ] = None,
        validate_phone_number: Union[
            Callable[[str, str], Awaitable[Union[str, None]]], None
        ] = None,
    ):
        super().__init__("EMAIL_OR_PHONE")

        if validate_email_address is None:
            self.validate_email_address = default_validate_email
        else:
            self.validate_email_address = validate_email_address

        if validate_phone_number is None:
            self.validate_phone_number = default_validate_phone_number
        else:
            self.validate_phone_number = validate_phone_number


class PhoneOrEmailInput:
    def __init__(self, phone_number: Union[str, None], email: Union[str, None]):
        self.phone_number = phone_number
        self.email = email


class PasswordlessConfig:
    def __init__(
        self,
        contact_config: ContactConfig,
        override: OverrideConfig,
        flow_type: Literal[
            "USER_INPUT_CODE", "MAGIC_LINK", "USER_INPUT_CODE_AND_MAGIC_LINK"
        ],
        get_email_delivery_config: Callable[
            [], EmailDeliveryConfigWithService[PasswordlessLoginEmailTemplateVars]
        ],
        get_sms_delivery_config: Callable[
            [], SMSDeliveryConfigWithService[PasswordlessLoginSMSTemplateVars]
        ],
        get_custom_user_input_code: Union[
            Callable[[str, Dict[str, Any]], Awaitable[str]], None
        ] = None,
    ):
        self.contact_config = contact_config
        self.override = override
        self.flow_type: Literal[
            "USER_INPUT_CODE", "MAGIC_LINK", "USER_INPUT_CODE_AND_MAGIC_LINK"
        ] = flow_type
        self.get_custom_user_input_code = get_custom_user_input_code
        self.get_email_delivery_config = get_email_delivery_config
        self.get_sms_delivery_config = get_sms_delivery_config


def validate_and_normalise_user_input(
    app_info: AppInfo,
    contact_config: ContactConfig,
    flow_type: Literal[
        "USER_INPUT_CODE", "MAGIC_LINK", "USER_INPUT_CODE_AND_MAGIC_LINK"
    ],
    override: Union[OverrideConfig, None] = None,
    get_custom_user_input_code: Union[
        Callable[[str, Dict[str, Any]], Awaitable[str]], None
    ] = None,
    email_delivery: Union[
        EmailDeliveryConfig[PasswordlessLoginEmailTemplateVars], None
    ] = None,
    sms_delivery: Union[
        SMSDeliveryConfig[PasswordlessLoginSMSTemplateVars], None
    ] = None,
) -> PasswordlessConfig:

    if override is None:
        override = OverrideConfig()

    def get_email_delivery_config() -> EmailDeliveryConfigWithService[
        PasswordlessLoginEmailTemplateVars
    ]:
        email_service = email_delivery.service if email_delivery is not None else None

        if email_service is None:
            email_service = BackwardCompatibilityService(app_info)

        if email_delivery is not None and email_delivery.override is not None:
            override = email_delivery.override
        else:
            override = None

        return EmailDeliveryConfigWithService(email_service, override=override)

    def get_sms_delivery_config() -> SMSDeliveryConfigWithService[
        PasswordlessLoginSMSTemplateVars
    ]:
        sms_service = sms_delivery.service if sms_delivery is not None else None

        if sms_service is None:
            sms_service = SMSBackwardCompatibilityService(app_info)

        if sms_delivery is not None and sms_delivery.override is not None:
            override = sms_delivery.override
        else:
            override = None

        return SMSDeliveryConfigWithService(sms_service, override=override)

    if not isinstance(contact_config, ContactConfig):  # type: ignore user might not have linter enabled
        raise ValueError("contact_config must be of type ContactConfig")

    if flow_type not in [
        "USER_INPUT_CODE",
        "MAGIC_LINK",
        "USER_INPUT_CODE_AND_MAGIC_LINK",
    ]:
        raise ValueError(
            "flow_type must be one of USER_INPUT_CODE, MAGIC_LINK, USER_INPUT_CODE_AND_MAGIC_LINK"
        )

    if not isinstance(override, OverrideConfig):  # type: ignore user might not have linter enabled
        raise ValueError("override must be of type OverrideConfig")

    return PasswordlessConfig(
        contact_config=contact_config,
        override=OverrideConfig(functions=override.functions, apis=override.apis),
        flow_type=flow_type,
        get_email_delivery_config=get_email_delivery_config,
        get_sms_delivery_config=get_sms_delivery_config,
        get_custom_user_input_code=get_custom_user_input_code,
    )
