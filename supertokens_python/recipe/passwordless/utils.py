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
from re import fullmatch
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Dict, List, Optional, Union

from phonenumbers import is_valid_number, parse
from typing_extensions import Literal

from supertokens_python.ingredients.emaildelivery.types import (
    EmailDeliveryConfig,
    EmailDeliveryConfigWithService,
)
from supertokens_python.ingredients.smsdelivery.types import (
    SMSDeliveryConfig,
    SMSDeliveryConfigWithService,
)
from supertokens_python.recipe.multifactorauth.types import FactorIds
from supertokens_python.recipe.passwordless.emaildelivery.services.backward_compatibility import (
    BackwardCompatibilityService,
)
from supertokens_python.recipe.passwordless.smsdelivery.services.backward_compatibility import (
    BackwardCompatibilityService as SMSBackwardCompatibilityService,
)
from supertokens_python.recipe.passwordless.types import (
    PasswordlessLoginSMSTemplateVars,
)
from supertokens_python.types.config import (
    BaseConfig,
    BaseInputConfig,
    BaseInputOverrideConfig,
    BaseOverrideConfig,
)
from supertokens_python.types.utils import UseDefaultIfNone

from .interfaces import (
    APIInterface,
    PasswordlessLoginEmailTemplateVars,
    RecipeInterface,
)

if TYPE_CHECKING:
    from supertokens_python import AppInfo


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


class InputOverrideConfig(BaseInputOverrideConfig[RecipeInterface, APIInterface]): ...


class OverrideConfig(BaseOverrideConfig[RecipeInterface, APIInterface]): ...


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


class PasswordlessInputConfig(BaseInputConfig[RecipeInterface, APIInterface]):
    contact_config: ContactConfig
    flow_type: Literal[
        "USER_INPUT_CODE", "MAGIC_LINK", "USER_INPUT_CODE_AND_MAGIC_LINK"
    ]
    get_custom_user_input_code: Union[
        Callable[[str, Dict[str, Any]], Awaitable[str]], None
    ] = None
    email_delivery: Union[
        EmailDeliveryConfig[PasswordlessLoginEmailTemplateVars], None
    ] = None
    sms_delivery: Union[SMSDeliveryConfig[PasswordlessLoginSMSTemplateVars], None] = (
        None
    )
    override: UseDefaultIfNone[Optional[InputOverrideConfig]] = InputOverrideConfig()  # type: ignore - https://github.com/microsoft/pyright/issues/5933


class PasswordlessConfig(BaseConfig[RecipeInterface, APIInterface]):
    contact_config: ContactConfig
    flow_type: Literal[
        "USER_INPUT_CODE", "MAGIC_LINK", "USER_INPUT_CODE_AND_MAGIC_LINK"
    ]
    get_email_delivery_config: Callable[
        [], EmailDeliveryConfigWithService[PasswordlessLoginEmailTemplateVars]
    ]
    get_sms_delivery_config: Callable[
        [], SMSDeliveryConfigWithService[PasswordlessLoginSMSTemplateVars]
    ]
    get_custom_user_input_code: Union[
        Callable[[str, Dict[str, Any]], Awaitable[str]], None
    ]
    override: OverrideConfig  # type: ignore - https://github.com/microsoft/pyright/issues/5933


def validate_and_normalise_user_input(
    app_info: AppInfo,
    input_config: PasswordlessInputConfig,
) -> PasswordlessConfig:
    override_config = OverrideConfig()
    if input_config.override is not None:
        if input_config.override.functions is not None:
            override_config.functions = input_config.override.functions

        if input_config.override.apis is not None:
            override_config.apis = input_config.override.apis

    def get_email_delivery_config() -> EmailDeliveryConfigWithService[
        PasswordlessLoginEmailTemplateVars
    ]:
        email_service = (
            input_config.email_delivery.service
            if input_config.email_delivery is not None
            else None
        )

        if email_service is None:
            email_service = BackwardCompatibilityService(app_info)

        if (
            input_config.email_delivery is not None
            and input_config.email_delivery.override is not None
        ):
            override = input_config.email_delivery.override
        else:
            override = None

        return EmailDeliveryConfigWithService(email_service, override=override)

    def get_sms_delivery_config() -> SMSDeliveryConfigWithService[
        PasswordlessLoginSMSTemplateVars
    ]:
        sms_service = (
            input_config.sms_delivery.service
            if input_config.sms_delivery is not None
            else None
        )

        if sms_service is None:
            sms_service = SMSBackwardCompatibilityService(app_info)

        if (
            input_config.sms_delivery is not None
            and input_config.sms_delivery.override is not None
        ):
            override = input_config.sms_delivery.override
        else:
            override = None

        return SMSDeliveryConfigWithService(sms_service, override=override)

    if not isinstance(input_config.contact_config, ContactConfig):  # type: ignore user might not have linter enabled
        raise ValueError("contact_config must be of type ContactConfig")

    if input_config.flow_type not in [
        "USER_INPUT_CODE",
        "MAGIC_LINK",
        "USER_INPUT_CODE_AND_MAGIC_LINK",
    ]:
        raise ValueError(
            "flow_type must be one of USER_INPUT_CODE, MAGIC_LINK, USER_INPUT_CODE_AND_MAGIC_LINK"
        )

    return PasswordlessConfig(
        contact_config=input_config.contact_config,
        override=override_config,
        flow_type=input_config.flow_type,
        get_email_delivery_config=get_email_delivery_config,
        get_sms_delivery_config=get_sms_delivery_config,
        get_custom_user_input_code=input_config.get_custom_user_input_code,
    )


def get_enabled_pwless_factors(
    config: PasswordlessConfig,
) -> List[str]:
    all_factors: List[str] = []

    if config.flow_type == "MAGIC_LINK":
        if config.contact_config.contact_method == "EMAIL":
            all_factors = [FactorIds.LINK_EMAIL]
        elif config.contact_config.contact_method == "PHONE":
            all_factors = [FactorIds.LINK_PHONE]
        else:
            all_factors = [FactorIds.LINK_EMAIL, FactorIds.LINK_PHONE]
    elif config.flow_type == "USER_INPUT_CODE":
        if config.contact_config.contact_method == "EMAIL":
            all_factors = [FactorIds.OTP_EMAIL]
        elif config.contact_config.contact_method == "PHONE":
            all_factors = [FactorIds.OTP_PHONE]
        else:
            all_factors = [FactorIds.OTP_EMAIL, FactorIds.OTP_PHONE]
    else:
        if config.contact_config.contact_method == "EMAIL":
            all_factors = [FactorIds.OTP_EMAIL, FactorIds.LINK_EMAIL]
        elif config.contact_config.contact_method == "PHONE":
            all_factors = [FactorIds.OTP_PHONE, FactorIds.LINK_PHONE]
        else:
            all_factors = [
                FactorIds.OTP_EMAIL,
                FactorIds.OTP_PHONE,
                FactorIds.LINK_EMAIL,
                FactorIds.LINK_PHONE,
            ]

    return all_factors
